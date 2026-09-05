from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
try:
    import age_tool
    import local_handoff as handoff
finally:
    sys.path.pop(0)

SPEC = importlib.util.spec_from_file_location("local_validator", ROOT / "scripts/validate-repository.py")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

RECIPIENT = "age1" + "q" * 58
POLICY = {
    "schema_version": 1, "profiles": ["subvocal", "subvocal-light"],
    "staging_release": "local-handoffs", "signing_recipient": RECIPIENT,
}


def inputs() -> dict:
    return {
        "app": "subvocal", "tag": "v2.0.0", "source_sha": "a" * 40,
        "source_ref_sha": "a" * 40, "source_tag_object_sha": "",
        "archive_sha256": "b" * 64, "return_recipient": RECIPIENT,
        "request_id": "local-" + "c" * 32,
    }


class LocalHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.policy = self.root / "policy.json"
        self.policy.write_text(json.dumps(POLICY))
        patch = mock.patch.object(handoff, "CONFIG", self.policy)
        patch.start()
        self.addCleanup(patch.stop)

    def test_inputs_are_a_closed_owner_attestation(self) -> None:
        self.assertEqual(handoff.validate_inputs(inputs()), inputs())
        changes = [
            {"app": "openwritr"}, {"tag": "v2.0.0;echo injected"},
            {"source_sha": "main"}, {"archive_sha256": "../input"},
            {"return_recipient": "https://attacker.test"}, {"request_id": "other"},
            {"source_ref_sha": "f" * 40}, {"source_tag_object_sha": "f" * 40},
            {"repository": "attacker/source"},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises((ValueError, handoff.broker.BrokerError)):
                handoff.validate_inputs(inputs() | change)

    def test_annotated_source_tags_bind_outer_ref(self) -> None:
        values = inputs() | {"source_ref_sha": "d" * 40, "source_tag_object_sha": "d" * 40}
        self.assertEqual(handoff.validate_inputs(values), values)

    def test_runner_rejects_forks_other_owners_and_reruns(self) -> None:
        environment = {
            "GITHUB_REPOSITORY": handoff.REPOSITORY,
            "GITHUB_REPOSITORY_ID": str(handoff.REPOSITORY_ID),
            "GITHUB_ACTOR_ID": str(handoff.OWNER_ID), "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "e" * 40,
        } | {f"INPUT_{key.upper()}": value for key, value in inputs().items()}
        with mock.patch.dict(os.environ, environment, clear=True):
            request = handoff.runner_request()
            self.assertEqual(request["source_verification"], "owner-attested-local-build")
        for key, bad in (
            ("GITHUB_REPOSITORY", "attacker/broker"), ("GITHUB_ACTOR_ID", "42"),
            ("GITHUB_REF", "refs/heads/other"), ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_REPOSITORY_ID", "42"),
        ):
            with self.subTest(key=key), mock.patch.dict(os.environ, environment | {key: bad}, clear=True):
                with self.assertRaises(ValueError):
                    handoff.runner_request()

    def test_policy_has_no_remote_url_or_unconfigured_recipient(self) -> None:
        for change in ({"signing_recipient": ""}, {"staging_release": "attacker"},
                       {"profiles": ["subvocal", "other"]}):
            self.policy.write_text(json.dumps(POLICY | change))
            with self.assertRaises(ValueError):
                handoff.config()

    def test_transfer_unpack_accepts_only_exact_regular_files(self) -> None:
        source = self.root / "payload.json"
        source.write_text("{}")
        archive = self.root / "transfer.zip"
        handoff.pack_files(archive, {"payload.json": source})
        handoff.unpack_files(archive, self.root / "unpacked", {"payload.json"})
        self.assertEqual((self.root / "unpacked/payload.json").read_text(), "{}")
        self.assertEqual(stat.S_IMODE((self.root / "unpacked/payload.json").stat().st_mode), 0o600)

    def test_transfer_unpack_rejects_traversal_duplicates_symlinks_and_oversize(self) -> None:
        for case in ("traversal", "duplicate", "symlink", "oversize", "unexpected"):
            with self.subTest(case=case):
                archive = self.root / f"{case}.zip"
                with zipfile.ZipFile(archive, "w") as bundle:
                    name = "../payload" if case == "traversal" else "payload"
                    info = zipfile.ZipInfo(name)
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16 if case == "symlink" else 0
                    bundle.writestr(info, b"x" * (100 if case == "oversize" else 1))
                    if case == "duplicate":
                        bundle.writestr("payload", b"x")
                    if case == "unexpected":
                        bundle.writestr("private-source.swift", b"x")
                with mock.patch.object(handoff, "MAX_TRANSFER", 50), self.assertRaises(ValueError):
                    handoff.unpack_files(archive, self.root / case, {"payload"})

    def test_asset_download_rejects_other_uploaders_and_excessive_size_before_request(self) -> None:
        base = {"id": 10, "size": 3, "uploader": {"id": handoff.OWNER_ID},
                "state": "uploaded", "digest": "sha256:" + hashlib.sha256(b"abc").hexdigest()}
        for change in ({"uploader": {"id": 42}}, {"size": handoff.MAX_TRANSFER + 1},
                       {"state": "new"}, {"id": "../other"}):
            with mock.patch.object(subprocess, "run") as run, self.assertRaises(ValueError):
                handoff.download_asset(base | change, self.root / "download.age")
            run.assert_not_called()

    def test_asset_digest_is_verified(self) -> None:
        asset = {"id": 10, "size": 3, "uploader": {"id": handoff.OWNER_ID},
                 "state": "uploaded", "digest": "sha256:" + "0" * 64}
        def fake_run(command, **kwargs):
            kwargs["stdout"].write(b"abc")
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(subprocess, "run", side_effect=fake_run), self.assertRaises(ValueError):
            handoff.download_asset(asset, self.root / "download.age")

    def test_source_tag_change_is_rejected_locally(self) -> None:
        source = self.root / "source"
        (source / "Subvocal").mkdir(parents=True)
        profile = handoff.broker.get_profile("subvocal")
        (source / "Subvocal/Package.resolved").write_bytes(
            handoff.broker.safe_profile_path(profile["dependency_lock"]).read_bytes()
        )
        answers = [
            "", "a" * 40, "a" * 40,
            json.dumps({"id": profile["repository_id"], "full_name": profile["repository"]}),
            json.dumps({"object": {"sha": "d" * 40, "type": "commit"}}),
        ]
        with mock.patch.object(handoff, "invoke", side_effect=answers), self.assertRaises(ValueError):
            handoff.source_attestation(source, "subvocal", "v2.0.0")

    def test_run_identity_checks_workflow_commit_owner_and_attempt(self) -> None:
        state = {"broker_commit": "e" * 40}
        run = {"event": "workflow_dispatch", "head_branch": "main", "head_sha": "e" * 40,
               "run_attempt": 1, "actor": {"id": handoff.OWNER_ID},
               "repository": {"id": handoff.REPOSITORY_ID}, "path": ".github/workflows/notarize-local.yml"}
        handoff.verify_run(run, state)
        for change in ({"run_attempt": 2}, {"head_sha": "f" * 40}, {"actor": {"id": 42}},
                       {"path": ".github/workflows/notarize.yml"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                handoff.verify_run(run | change, state)

    def test_remote_failure_never_prints_python_or_subprocess_diagnostics(self) -> None:
        code = """
import sys, os, subprocess
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import local_handoff
local_handoff.age_tool.install = lambda path: Path("age")
def fail(work, age):
    print("PRIVATE-PYTHON-SENTINEL", flush=True)
    os.write(2, b"PRIVATE-STDERR-SENTINEL")
    subprocess.run([sys.executable, "-c", "print('PRIVATE-CHILD-SENTINEL')"])
    raise RuntimeError("PRIVATE-EXCEPTION-SENTINEL")
local_handoff.start = fail
raise SystemExit(local_handoff.remote("start"))
"""
        result = subprocess.run(
            [sys.executable, "-c", code, str(ROOT / "scripts")], cwd=self.root,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("PRIVATE-", result.stdout + result.stderr)
        self.assertIn("no private diagnostics", result.stderr)

    def test_age_checksum_and_tar_member_validation(self) -> None:
        for kind in ("valid", "symlink"):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                for name in ("age", "age-keygen"):
                    member = tarfile.TarInfo(f"age/{name}")
                    if kind == "symlink":
                        member.type = tarfile.SYMTYPE
                        member.linkname = "../../outside"
                        archive.addfile(member)
                    else:
                        member.size = 4
                        archive.addfile(member, io.BytesIO(b"test"))
            data = buffer.getvalue()
            destination = self.root / kind
            destination.mkdir()
            with self.assertRaises(ValueError):
                age_tool.unpack_verified(data, "0" * 64, destination)
            if kind == "symlink":
                with self.assertRaises(ValueError):
                    age_tool.unpack_verified(data, hashlib.sha256(data).hexdigest(), destination)
            else:
                age_tool.unpack_verified(data, hashlib.sha256(data).hexdigest(), destination)
                self.assertEqual((destination / "age").read_bytes(), b"test")

    def test_two_runner_handoff_binds_manifest_request_and_encrypted_results(self) -> None:
        original_cwd = Path.cwd()
        self.addCleanup(os.chdir, original_cwd)
        os.chdir(self.root)
        preflight = handoff.private_directory(self.root / "preflight")
        signing = handoff.private_directory(self.root / "signing")
        raw_archive = b"synthetic unsigned archive"
        values = inputs() | {"archive_sha256": hashlib.sha256(raw_archive).hexdigest()}
        profile_digest = handoff.broker.profile_digest("subvocal", handoff.broker.get_profile("subvocal"))
        request = {
            "inputs": values, "run_id": "123", "run_attempt": "1", "broker_commit": "e" * 40,
            "profile_digest": profile_digest, "handoff_policy_digest": handoff.broker.sha256_file(self.policy),
            "source_verification": "owner-attested-local-build", "schema_version": 1,
        }
        handoff.write_json(preflight / "request.json", request)
        (preflight / "preflight.identity").write_text("ephemeral")
        asset = {"id": 456, "name": handoff.input_asset_name(request)}
        tree_digest = "d" * 64
        manifest = {
            "profile": "subvocal", "version": "2.0.0", "profile_digest": profile_digest,
            "application": {"tree_sha256": tree_digest, "main_executable_sha256": "f" * 64,
                            "nested_executables": []},
        }

        def fake_validate(req, archive, work, **kwargs):
            self.assertEqual(req, request)
            self.assertEqual(handoff.broker.sha256_file(archive), kwargs["digest"])
            handoff.write_json(work / "preflight-manifest.json", manifest)
            if kwargs.get("repack"):
                (work / "validated-app.zip").write_bytes(b"sanitized synthetic app")
            else:
                self.assertEqual(kwargs["tree"], tree_digest)
            return manifest

        def fake_crypt(age, key, source, destination):
            shutil.copyfile(source, destination)

        def fake_sign(args):
            self.assertEqual(args.source_commit_sha, values["source_sha"])
            self.assertEqual(args.expected_tree_sha, tree_digest)
            output = Path(args.output_dir)
            output.mkdir()
            artifacts = []
            for declaration in handoff.broker.get_profile("subvocal")["artifacts"]:
                name = declaration["name"].format(version="2.0.0")
                (output / name).write_bytes(b"synthetic signed artifact")
                (output / (name + ".sha256")).write_text(handoff.broker.sha256_file(output / name))
                artifacts.append({"name": name, "sha256": handoff.broker.sha256_file(output / name)})
            handoff.write_json(output / "provenance.json", {
                "profile": "subvocal", "request_id": values["request_id"], "source": {},
                "broker": {"commit_sha": request["broker_commit"], "run_id": "123"},
                "artifacts": artifacts,
            })
            handoff.write_json(output / "preflight-manifest.json", manifest)

        with mock.patch.object(handoff, "runner_request", return_value=request), \
             mock.patch.object(handoff, "age_encrypt", side_effect=fake_crypt), \
             mock.patch.object(handoff, "age_decrypt", side_effect=fake_crypt), \
             mock.patch.object(handoff, "validate_archive", side_effect=fake_validate), \
             mock.patch.object(handoff.broker, "append_github_outputs") as outputs:
            with mock.patch.object(handoff, "api", return_value={"id": 1, "author": {"id": handoff.OWNER_ID}}), \
                 mock.patch.object(handoff, "release_assets", return_value=[asset]), \
                 mock.patch.object(handoff, "download_asset",
                                   side_effect=lambda asset, path: path.write_bytes(raw_archive)):
                handoff.preflight(preflight, Path("age"))
            self.assertFalse((preflight / "preflight.identity").exists())
            self.assertEqual(set(p.name for p in (preflight / "outbound").iterdir()), {"validated.age"})
            transport = preflight / "outbound/validated.age"
            encrypted_input = handoff.private_directory(self.root / "encrypted-input")
            shutil.copyfile(transport, encrypted_input / "validated.age")
            environment = {
                "EXPECTED_CIPHERTEXT_SHA256": handoff.broker.sha256_file(transport),
                "EXPECTED_TREE_SHA256": tree_digest, "LOCAL_HANDOFF_AGE_IDENTITY": "AGE-SECRET-KEY-TEST",
            }
            with mock.patch.dict(os.environ, environment), mock.patch.object(handoff, "invoke", return_value=RECIPIENT):
                handoff.sign_prepare(signing, Path("age"))
                self.assertNotIn("LOCAL_HANDOFF_AGE_IDENTITY", os.environ)
            self.assertFalse((signing / "signing.identity").exists())
            self.assertEqual(handoff.read_json(signing / "verified.json")["request"], request)
            with mock.patch.object(handoff.broker, "command_sign", side_effect=fake_sign) as sign:
                handoff.sign_finish(signing, Path("age"))
                sign.assert_called_once()
            self.assertEqual(set(p.name for p in (signing / "outbound").iterdir()), {"result.age"})
            provenance = handoff.read_json(signing / "signed/provenance.json")
            self.assertEqual(provenance["source"]["verification"], "owner-attested-local-build")
            self.assertEqual(provenance["local_handoff"]["request"]["inputs"], values)

    def test_signing_rejects_ciphertext_digest_before_decrypting(self) -> None:
        original_cwd = Path.cwd()
        self.addCleanup(os.chdir, original_cwd)
        os.chdir(self.root)
        handoff.private_directory(self.root / "encrypted-input")
        (self.root / "encrypted-input/validated.age").write_bytes(b"tampered")
        with mock.patch.object(handoff, "runner_request", return_value={}), \
             mock.patch.dict(os.environ, {"EXPECTED_CIPHERTEXT_SHA256": "0" * 64}), \
             mock.patch.object(handoff, "age_decrypt") as decrypt:
            with self.assertRaises(ValueError):
                handoff.sign_prepare(self.root, Path("age"))
            decrypt.assert_not_called()


class LocalWorkflowValidatorTests(unittest.TestCase):
    def test_shipped_signing_recipient_is_configured(self) -> None:
        self.assertEqual(
            handoff.config()["signing_recipient"],
            "age14m3cv78emtnddst0cetw53vpys5vy5r0wzqapfa4u0kt7skqffesy80cg2",
        )

    def test_actual_workflow_has_only_encrypted_artifact_paths(self) -> None:
        validator.validate_local_workflow(ROOT / ".github/workflows/notarize-local.yml")

    def test_local_workflow_rejects_weakened_boundaries(self) -> None:
        text = (ROOT / ".github/workflows/notarize-local.yml").read_text()
        substitutions = [
            ("environment: macos-signing", "environment: other"),
            ("github.run_attempt == 1", "true"),
            ("github.actor_id == '24534196'", "true"),
            ("path: .local-handoff/outbound/validated.age", "path: .local-handoff"),
            ("path: .local-handoff/outbound/result.age", "path: .local-handoff/signed"),
            ("artifact-ids: ${{ needs.preflight.outputs.artifact_id }}", "name: mutable-artifact"),
            ("run: python3 scripts/local_handoff.py sign-prepare", "run: source/build.sh"),
            ("LOCAL_HANDOFF_AGE_IDENTITY: ${{ secrets.LOCAL_HANDOFF_AGE_IDENTITY }}",
             "LOCAL_HANDOFF_AGE_IDENTITY: ${{ secrets.OTHER }}"),
            ("      contents: read", "      contents: write"),
            ("needs: preflight", "needs: unrelated"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "notarize-local.yml"
            for old, new in substitutions:
                with self.subTest(old=old), self.assertRaises(AssertionError):
                    path.write_text(text.replace(old, new))
                    validator.validate_local_workflow(path)
