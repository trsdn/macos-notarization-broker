from __future__ import annotations

import importlib.util
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("broker", ROOT / "scripts" / "broker.py")
assert SPEC and SPEC.loader
broker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(broker)


class ProfileTests(unittest.TestCase):
    def test_all_existing_profiles_are_declared(self) -> None:
        profiles = broker.load_profiles()
        self.assertEqual(
            set(profiles),
            {"md2loop", "openwritr", "ptionsplus", "teleprompter"},
        )

    def test_profile_repository_identities_are_fixed(self) -> None:
        profiles = broker.load_profiles()
        self.assertEqual(profiles["md2loop"]["repository_id"], 1168645937)
        self.assertEqual(profiles["openwritr"]["repository_id"], 1165782217)
        self.assertEqual(profiles["ptionsplus"]["repository_id"], 1165009675)
        self.assertEqual(profiles["teleprompter"]["repository_id"], 1339874326)

    def test_artifact_names_preserve_existing_release_contracts(self) -> None:
        profiles = broker.load_profiles()
        names = {
            name: [artifact["name"] for artifact in profile["artifacts"]]
            for name, profile in profiles.items()
        }
        self.assertEqual(names["md2loop"], ["md2loop-{version}-macos.dmg"])
        self.assertEqual(
            names["openwritr"],
            [
                "OpenWritr-v{version}-macOS-arm64.zip",
                "OpenWritr-v{version}-macOS-arm64.dmg",
            ],
        )
        self.assertEqual(names["ptionsplus"], ["Ptions+.zip", "Ptions+.dmg"])
        self.assertEqual(
            names["teleprompter"],
            ["Teleprompter-Mirror-v{version}-macOS-arm64.zip"],
        )


class InputValidationTests(unittest.TestCase):
    def test_tag_validation(self) -> None:
        self.assertEqual(broker.validate_tag("v1.2.3"), "1.2.3")
        self.assertEqual(broker.validate_tag("v1.2.3-rc.1"), "1.2.3-rc.1")
        for invalid in (
            "main",
            "1.2.3",
            "v1",
            "v1.2.3/../../main",
            "v1.2.3$(id)",
            "v1.2.3\nmain",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(broker.BrokerError):
                    broker.validate_tag(invalid)

    def test_request_id_validation(self) -> None:
        self.assertEqual(broker.normalize_request_id("req-123"), "req-123")
        for invalid in ("../request", "with space", "req-$(id)", "x" * 81):
            with self.subTest(invalid=invalid):
                with self.assertRaises(broker.BrokerError):
                    broker.normalize_request_id(invalid)

    def test_zip_path_validation_rejects_traversal(self) -> None:
        for invalid in ("../evil", "/absolute", "Root.app\\..\\evil", "a/\x00b"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(broker.BrokerError):
                    broker.normalized_zip_path(invalid)


class ArchiveValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = broker.get_profile("teleprompter")

    def test_archive_rejects_content_outside_expected_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "bad.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("unexpected.txt", "bad")
            with self.assertRaises(broker.BrokerError):
                broker.inspect_zip(archive, self.profile)

    def test_archive_rejects_symlink_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "symlink.zip"
            entry = zipfile.ZipInfo("Teleprompter Mirror.app/Contents/MacOS/link")
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr(entry, "../../outside")
            with self.assertRaises(broker.BrokerError):
                broker.inspect_zip(archive, self.profile)

    def test_archive_rejects_appledouble_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "appledouble.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("Teleprompter Mirror.app/Contents/._Info.plist", "bad")
            with self.assertRaises(broker.BrokerError):
                broker.inspect_zip(archive, self.profile)


class SignedEntitlementsTests(unittest.TestCase):
    ENTITLEMENTS_XML = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        b'"https://www.apple.com/DTDs/PropertyList-1.0.dtd">'
        b'<plist version="1.0"><dict/></plist>\n'
    )

    def test_codesign_diagnostics_are_not_appended_to_stdout_plist(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=self.ENTITLEMENTS_XML,
            stderr=(
                b"Executable=/tmp/Teleprompter Mirror.app/Contents/MacOS/"
                b"TeleprompterMirror\n"
            ),
        )
        with mock.patch.object(
            broker.subprocess, "run", return_value=completed
        ) as codesign:
            entitlements = broker.read_signed_entitlements(
                Path("/tmp/Teleprompter Mirror.app")
            )

        self.assertEqual(entitlements, {})
        codesign.assert_called_once_with(
            [
                "codesign",
                "-d",
                "--xml",
                "--entitlements",
                "-",
                "/tmp/Teleprompter Mirror.app",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_xml_plist_is_bounded_when_codesign_uses_stderr(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=b"",
            stderr=(
                b"Executable=/tmp/Test.app/Contents/MacOS/Test\n"
                + self.ENTITLEMENTS_XML
                + b"codesign diagnostic after plist\n"
            ),
        )
        with mock.patch.object(broker.subprocess, "run", return_value=completed):
            entitlements = broker.read_signed_entitlements(Path("/tmp/Test.app"))

        self.assertEqual(entitlements, {})


if __name__ == "__main__":
    unittest.main()
