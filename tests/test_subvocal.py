from __future__ import annotations

import argparse
import json
import plistlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_broker import BundleFixtureMixin, broker


class SubvocalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def fixture(self, name: str = "subvocal") -> tuple[Path, Path, dict, Path]:
        profile = broker.get_profile(name)
        source = self.root / name / "source"
        package = source / "Subvocal"
        package.mkdir(parents=True)
        (package / "Package.swift").write_text("// fixture")
        shutil.copy2(
            broker.safe_profile_path(profile["dependency_lock"]), package / "Package.resolved"
        )
        flavor = "Subvocal" if name == "subvocal" else "SubvocalLightApp"
        plist_path = package / "Sources" / flavor / "Info.plist"
        plist_path.parent.mkdir(parents=True)
        plist_path.write_bytes(plistlib.dumps({
            "CFBundleIdentifier": profile["bundle_identifier"],
            "CFBundleExecutable": profile["executable"],
            "CFBundleDisplayName": profile["bundle_display_name"],
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "2.0.0",
            "CFBundleVersion": "2.0.0",
            "LSMinimumSystemVersion": "15.0",
            "LSUIElement": name == "subvocal",
            "NSMicrophoneUsageDescription": "Microphone",
            "NSAudioCaptureUsageDescription": "System audio",
        }))
        icon = package / "Sources/Subvocal/Assets/AppIcon.icns"
        icon.parent.mkdir(parents=True, exist_ok=True)
        icon.write_bytes(b"icon")
        binary = package / ".build/release" / profile["executable"]
        binary.parent.mkdir(parents=True)
        binary.write_bytes(BundleFixtureMixin.ARM64_MACHO)
        binary.chmod(0o755)
        for spec in broker.nested_resource_bundles(profile):
            bundle = binary.parent / Path(spec["path"]).name
            bundle.mkdir()
            (bundle / "Info.plist").write_bytes(plistlib.dumps({"CFBundlePackageType": "BNDL"}))
            (bundle / "data.json").write_text("{}")
        work = source.parent / "work"
        work.mkdir()
        return source, work, profile, binary

    def validate(self, app: Path, profile: dict) -> dict:
        def fake_run(command, **kwargs):
            if command[0] == "file":
                return subprocess.CompletedProcess(command, 0, "Mach-O 64-bit executable arm64")
            if command[0] == "lipo":
                return subprocess.CompletedProcess(command, 0, "arm64")
            raise AssertionError(command)
        with mock.patch.object(broker, "run", side_effect=fake_run):
            return broker.validate_app_tree(app, profile, "2.0.0", require_unsigned=False)

    def test_both_profiles_pin_identity_outputs_and_microphone_only(self) -> None:
        for name, executable, identifier in (
            ("subvocal", "Subvocal", "com.subvocal.app"),
            ("subvocal-light", "SubvocalLight", "com.subvocal.light"),
        ):
            with self.subTest(name=name):
                profile = broker.get_profile(name)
                self.assertEqual(profile["repository"], "trsdn/Subvocal")
                self.assertEqual(profile["repository_id"], 1197322196)
                self.assertEqual(profile["source_visibility"], "private")
                self.assertEqual(profile["executable"], executable)
                self.assertEqual(profile["bundle_identifier"], identifier)
                self.assertEqual(profile["architectures"], ["arm64"])
                self.assertEqual(profile["minimum_system_version"], "15.0")
                self.assertEqual(
                    [item["name"] for item in profile["artifacts"]],
                    [f"{executable}-v{{version}}-macOS-arm64.zip", f"{executable}.dmg"],
                )
                self.assertNotIn("provisioning_profile", profile)
                self.assertFalse(broker.nested_executables(profile))
                entitlements = plistlib.loads(broker.safe_profile_path(profile["entitlements"]).read_bytes())
                self.assertEqual(entitlements, {"com.apple.security.device.audio-input": True})

    def test_dependency_contract_pins_every_revision(self) -> None:
        profile = broker.get_profile("subvocal")
        lock = json.loads(broker.safe_profile_path(profile["dependency_lock"]).read_text())
        self.assertEqual(len(lock["pins"]), 6)
        for pin in lock["pins"]:
            self.assertRegex(pin["state"]["revision"], r"^[0-9a-f]{40}$")
            self.assertTrue(pin["location"].startswith("https://github.com/"))

    def test_both_adapters_package_resources_and_preserve_source_metadata(self) -> None:
        for name in ("subvocal", "subvocal-light"):
            with self.subTest(name=name):
                source, work, profile, binary = self.fixture(name)
                with mock.patch.object(broker, "swift_build", return_value=binary) as build:
                    app = broker.assemble_subvocal(source, work, profile)
                build.assert_called_once_with(source / "Subvocal", profile["executable"], require_lock=True)
                self.assertEqual(app.name, profile["bundle_name"])
                self.assertEqual(self.validate(app, profile)["bundle_version"], "2.0.0")
                self.assertEqual((app / "Contents/PkgInfo").read_bytes(), b"APPL????")
                self.assertEqual((app / "Contents/Resources/AppIcon.icns").read_bytes(), b"icon")

    def test_lock_mismatch_fails_before_compilation(self) -> None:
        source, work, profile, binary = self.fixture()
        (source / "Subvocal/Package.resolved").write_text("{}")
        with mock.patch.object(broker, "swift_build") as build:
            with self.assertRaisesRegex(broker.BrokerError, "dependency lock"):
                broker.assemble_subvocal(source, work, profile)
            build.assert_not_called()

    def test_lock_mutation_during_build_is_rejected(self) -> None:
        source, work, profile, binary = self.fixture()
        def build(*args, **kwargs):
            (source / "Subvocal/Package.resolved").write_text("{}")
            return binary
        with mock.patch.object(broker, "swift_build", side_effect=build):
            with self.assertRaisesRegex(broker.BrokerError, "changed during compilation"):
                broker.assemble_subvocal(source, work, profile)

    def test_missing_resource_is_rejected_by_adapter(self) -> None:
        source, work, profile, binary = self.fixture()
        shutil.rmtree(binary.parent / "PLCrashReporter_CrashReporter.bundle")
        with mock.patch.object(broker, "swift_build", return_value=binary):
            with self.assertRaisesRegex(broker.BrokerError, "resource bundle"):
                broker.assemble_subvocal(source, work, profile)

    def test_readonly_resources_are_writable_only_in_the_packaged_copy(self) -> None:
        source, work, profile, binary = self.fixture()
        resource = binary.parent / "PLCrashReporter_CrashReporter.bundle/data.json"
        resource.chmod(0o444)
        with mock.patch.object(broker, "swift_build", return_value=binary):
            app = broker.assemble_subvocal(source, work, profile)
        self.assertEqual(resource.stat().st_mode & 0o777, 0o444)
        packaged = app / "Contents/Resources/PLCrashReporter_CrashReporter.bundle/data.json"
        self.assertEqual(packaged.stat().st_mode & 0o777, 0o644)

    def test_resource_normalization_preserves_executable_rejection(self) -> None:
        source, work, profile, binary = self.fixture()
        resource = binary.parent / "PLCrashReporter_CrashReporter.bundle/data.json"
        resource.chmod(0o555)
        with mock.patch.object(broker, "swift_build", return_value=binary):
            app = broker.assemble_subvocal(source, work, profile)
        with self.assertRaisesRegex(broker.BrokerError, "Unexpected executable file"):
            self.validate(app, profile)

    def test_preflight_rejects_advertised_protected_artifacts(self) -> None:
        source, work, profile, binary = self.fixture()
        with mock.patch.object(broker, "swift_build", return_value=binary):
            app = broker.assemble_subvocal(source, work, profile)
        path = app / "Contents/Info.plist"
        info = plistlib.loads(path.read_bytes())
        info["SubvocalArtifactKeyAccessGroup"] = "ABCDE12345.example"
        path.write_bytes(plistlib.dumps(info))
        with self.assertRaisesRegex(broker.BrokerError, "protected artifact"):
            self.validate(app, profile)

    def test_preflight_requires_both_resource_bundles(self) -> None:
        source, work, profile, binary = self.fixture()
        with mock.patch.object(broker, "swift_build", return_value=binary):
            app = broker.assemble_subvocal(source, work, profile)
        shutil.rmtree(app / "Contents/Resources/PLCrashReporter_CrashReporter.bundle")
        with self.assertRaisesRegex(broker.BrokerError, "resource bundle is missing"):
            self.validate(app, profile)

    def test_preflight_still_rejects_code_inside_declared_resources(self) -> None:
        source, work, profile, binary = self.fixture()
        with mock.patch.object(broker, "swift_build", return_value=binary):
            app = broker.assemble_subvocal(source, work, profile)
        payload = app / "Contents/Resources/Subvocal_SubvocalKit.bundle/hidden"
        payload.write_bytes(BundleFixtureMixin.ARM64_MACHO)
        with self.assertRaisesRegex(broker.BrokerError, "Unexpected nested Mach-O"):
            self.validate(app, profile)

    def test_flavor_and_privacy_contract_is_enforced(self) -> None:
        profile = broker.get_profile("subvocal")
        base = {"LSUIElement": True, "NSMicrophoneUsageDescription": "Mic",
                "NSAudioCaptureUsageDescription": "Audio"}
        for change in ({"LSUIElement": False}, {"NSMicrophoneUsageDescription": ""},
                       {"NSAudioCaptureUsageDescription": None},
                       {"SubvocalArtifactKeyAccessGroup": ""}):
            with self.subTest(change=change), self.assertRaises(broker.BrokerError):
                broker.validate_subvocal_capabilities(base | change, profile)

    def test_shared_keychain_requires_provisioning(self) -> None:
        profile = broker.get_profile("subvocal")
        with self.assertRaisesRegex(broker.BrokerError, "without a provisioning"):
            broker.validate_provisioning_policy(
                "subvocal", profile, {"keychain-access-groups": ["ABCDE12345.example"]}
            )

    def test_private_profile_fails_before_api_access(self) -> None:
        args = argparse.Namespace(app="subvocal", tag="v2.0.0", request_id="test")
        with mock.patch.object(broker, "github_api") as api:
            with self.assertRaisesRegex(broker.BrokerError, "Private source support"):
                broker.command_resolve(args)
            api.assert_not_called()

    def test_private_repository_cannot_be_resolved_as_public(self) -> None:
        args = argparse.Namespace(app="openwritr", tag="v2.0.0", request_id="test")
        with mock.patch.object(broker, "github_api", return_value={"private": True}) as api:
            with self.assertRaisesRegex(broker.BrokerError, "Private source"):
                broker.command_resolve(args)
            self.assertEqual(api.call_count, 1)

    def test_private_profile_fails_before_build_commands(self) -> None:
        args = argparse.Namespace(app="subvocal", version="2.0.0")
        with mock.patch.object(broker, "require_tools"), mock.patch.object(broker, "run") as run:
            with self.assertRaisesRegex(broker.BrokerError, "Private source support"):
                broker.command_build(args)
            run.assert_not_called()

    def test_invalid_visibility_is_rejected(self) -> None:
        document = json.loads(broker.PROFILE_FILE.read_text())
        document["profiles"]["subvocal"]["source_visibility"] = "privat"
        path = self.root / "profiles.json"
        path.write_text(json.dumps(document))
        with mock.patch.object(broker, "PROFILE_FILE", path):
            with self.assertRaisesRegex(broker.BrokerError, "source visibility"):
                broker.load_profiles()

    def test_swift_build_requires_resolved_versions(self) -> None:
        source, work, profile, binary = self.fixture()
        def fake_run(command, **kwargs):
            self.assertIn("--only-use-versions-from-resolved-file", command)
            return subprocess.CompletedProcess(command, 0, str(binary.parent))
        with mock.patch.object(broker, "run", side_effect=fake_run):
            self.assertEqual(
                broker.swift_build(source / "Subvocal", "Subvocal", require_lock=True), binary
            )
