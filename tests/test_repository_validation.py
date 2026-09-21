from __future__ import annotations

import contextlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "validate_repository", ROOT / "scripts" / "validate-repository.py"
)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


SAFE_WORKFLOW = """name: CI

on:
  pull_request:
    branches:
      - main

permissions: {}

jobs:
  validate:
    name: Tests
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Check out repository
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          persist-credentials: false

      - name: Run broker unit tests
        run: |
          set -euo pipefail
          python3 -m unittest discover -s tests -v
"""

MIGRATION_WORKFLOW = """name: Migrate signing secrets

on:
  workflow_dispatch:

permissions: {}

jobs:
  migrate:
    if: >-
      github.event_name == 'workflow_dispatch' &&
      github.ref == 'refs/heads/main' &&
      github.repository == 'trsdn/macos-notarization-broker' &&
      github.event.repository.id == 1315404585 &&
      github.actor_id == '24534196'
    runs-on: ubuntu-latest
    environment: macos-signing
    permissions:
      contents: read
    steps:
      - name: Check out immutable broker
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          ref: ${{ github.sha }}
          persist-credentials: false
      - name: Install library
        run: sudo apt-get update -qq && sudo apt-get install -y -qq libsodium23
      - name: Seal values
        env:
          APPLE_ID: ${{ secrets.APPLE_ID }}
          APPLE_APP_PASSWORD: ${{ secrets.APPLE_APP_PASSWORD }}
          APPLE_TEAM_ID: ${{ secrets.APPLE_TEAM_ID }}
          MACOS_CERTIFICATE: ${{ secrets.MACOS_CERTIFICATE }}
          MACOS_CERTIFICATE_PWD: ${{ secrets.MACOS_CERTIFICATE_PWD }}
        run: python3 scripts/migrate-signing-secrets.py
      - name: Upload ciphertext
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
        with:
          path: sealed-signing-secrets.json
          if-no-files-found: error
          retention-days: 1
"""


class RepositoryValidatorTests(unittest.TestCase):
    def assert_workflow_rejected(self, workflow: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "supporting.yml"
            path.write_text(workflow, encoding="utf-8")
            with self.assertRaises(AssertionError):
                validator.validate_supporting_workflow(path)

    def test_repository_workflows_satisfy_static_policy(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(validator.main(), 0)

    def test_safe_supporting_workflow_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "supporting.yml"
            path.write_text(SAFE_WORKFLOW, encoding="utf-8")
            validator.validate_supporting_workflow(path)

    def test_supporting_workflow_may_not_reference_secrets(self) -> None:
        self.assert_workflow_rejected(
            SAFE_WORKFLOW.replace(
                "      - name: Run broker unit tests",
                "      - name: Leak\n        env:\n"
                "          TEAM: ${{ secrets.APPLE_TEAM_ID }}\n"
                "      - name: Run broker unit tests",
            )
        )

    def test_supporting_workflow_may_not_use_an_environment(self) -> None:
        self.assert_workflow_rejected(
            SAFE_WORKFLOW.replace(
                "    runs-on: ubuntu-latest",
                "    runs-on: ubuntu-latest\n    environment: macos-signing",
            )
        )

    def test_supporting_workflow_may_not_grant_write_permissions(self) -> None:
        self.assert_workflow_rejected(
            SAFE_WORKFLOW.replace("      contents: read", "      contents: write")
        )

    def test_supporting_workflow_requires_empty_top_level_permissions(self) -> None:
        self.assert_workflow_rejected(
            SAFE_WORKFLOW.replace("permissions: {}", "permissions: write-all")
        )

    def test_supporting_workflow_requires_sha_pinned_actions(self) -> None:
        self.assert_workflow_rejected(
            SAFE_WORKFLOW.replace(
                "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4",
                "actions/checkout@v4",
            )
        )

    def test_supporting_workflow_may_not_interpolate_expressions_into_shell(self) -> None:
        self.assert_workflow_rejected(
            SAFE_WORKFLOW.replace(
                "          python3 -m unittest discover -s tests -v",
                "          echo ${{ github.event.head_commit.message }}",
            )
        )

    def test_supporting_workflow_may_not_use_pull_request_target(self) -> None:
        self.assert_workflow_rejected(
            SAFE_WORKFLOW.replace("  pull_request:", "  pull_request_target:")
        )


class MigrationWorkflowValidatorTests(unittest.TestCase):
    def validate(self, text: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "migrate-signing-secrets.yml"
            path.write_text(text)
            validator.validate_migration_workflow(path)

    def test_protected_owner_only_migration_is_accepted(self) -> None:
        self.validate(MIGRATION_WORKFLOW)

    def test_migration_exemption_does_not_apply_to_supporting_workflows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ci.yml"
            path.write_text(MIGRATION_WORKFLOW)
            with self.assertRaises(AssertionError):
                validator.validate_supporting_workflow(path)

    def test_each_security_boundary_is_required(self) -> None:
        substitutions = [
            ("  workflow_dispatch:", "  push:"),
            ("  workflow_dispatch:", "  workflow_dispatch:\n    inputs:\n      recipient:\n        type: string"),
            ("environment: macos-signing", "environment: unprotected"),
            ("      contents: read", "      contents: write"),
            ("github.actor_id == '24534196'", "true"),
            ("github.ref == 'refs/heads/main'", "true"),
            ("github.event.repository.id == 1315404585", "true"),
            ("persist-credentials: false", "persist-credentials: true"),
            ("ref: ${{ github.sha }}", "ref: main"),
            ("scripts/migrate-signing-secrets.py", "source/migrate.py"),
            ("secrets.APPLE_ID", "secrets.UNRELATED"),
            ("          APPLE_ID:", "      APPLE_ID:"),
            ("actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
             "actions/checkout@main"),
            ("run: python3 scripts/migrate-signing-secrets.py",
             "run: python3 scripts/migrate-signing-secrets.py ${{ inputs.command }}"),
            ("path: sealed-signing-secrets.json", "path: ./"),
            ("retention-days: 1", "retention-days: 90"),
        ]
        for old, new in substitutions:
            with self.subTest(old=old), self.assertRaises(AssertionError):
                self.validate(MIGRATION_WORKFLOW.replace(old, new))


class AttestJobPolicyTests(unittest.TestCase):
    """The attest job is the one place a workflow here may write, and only this much."""

    WORKFLOW_TEXT = (ROOT / ".github" / "workflows" / "notarize.yml").read_text(encoding="utf-8")

    def assert_rejected(self, mutated: str) -> None:
        self.assertNotEqual(mutated, self.WORKFLOW_TEXT, "the mutation did not change the workflow")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "notarize.yml"
            path.write_text(mutated, encoding="utf-8")
            with mock.patch.object(validator, "WORKFLOW", path):
                with self.assertRaises(AssertionError):
                    validator.validate_notarize_workflow()

    def test_the_real_workflow_is_accepted(self) -> None:
        validator.validate_notarize_workflow()

    def test_missing_attest_job_is_rejected(self) -> None:
        head = self.WORKFLOW_TEXT.split("\n  attest:\n", 1)[0]
        self.assert_rejected(head + "\n")

    def test_attest_job_may_not_gain_a_permission(self) -> None:
        self.assert_rejected(
            self.WORKFLOW_TEXT.replace("      id-token: write\n", "      id-token: write\n      packages: write\n")
        )

    def test_attest_job_may_not_write_contents(self) -> None:
        head, tail = self.WORKFLOW_TEXT.split("\n  attest:\n", 1)
        self.assert_rejected(head + "\n  attest:\n" + tail.replace("contents: read", "contents: write", 1))

    def test_attest_job_may_not_lose_a_required_permission(self) -> None:
        head, tail = self.WORKFLOW_TEXT.split("\n  attest:\n", 1)
        self.assert_rejected(head + "\n  attest:\n" + tail.replace("      attestations: write\n", "", 1))

    def test_another_job_may_not_write(self) -> None:
        head, tail = self.WORKFLOW_TEXT.split("\n  preflight:\n", 1)
        self.assert_rejected(
            head + "\n  preflight:\n" + tail.replace("      contents: read\n", "      contents: write\n", 1)
        )

    def test_another_job_may_not_get_the_oidc_token(self) -> None:
        head, tail = self.WORKFLOW_TEXT.split("\n  build:\n", 1)
        self.assert_rejected(
            head + "\n  build:\n" + tail.replace("      contents: read\n", "      contents: read\n      id-token: write\n", 1)
        )

    def test_attest_job_may_not_reference_a_secret(self) -> None:
        self.assert_rejected(
            self.WORKFLOW_TEXT.replace(
                "          path: notarized\n",
                "          path: notarized\n          github-token: ${{ secrets.APPLE_ID }}\n",
            )
        )

    def test_attest_job_may_not_use_an_environment(self) -> None:
        self.assert_rejected(
            self.WORKFLOW_TEXT.replace(
                "    name: Attest the notarized artifacts\n",
                "    name: Attest the notarized artifacts\n    environment: macos-signing\n",
            )
        )

    def test_attest_job_may_not_run_a_shell(self) -> None:
        self.assert_rejected(
            self.WORKFLOW_TEXT.rstrip("\n")
            + "\n\n      - name: Extra\n        run: |\n          echo hello\n"
        )

    def test_attest_job_may_not_use_an_unpinned_action(self) -> None:
        self.assert_rejected(
            self.WORKFLOW_TEXT.replace(
                "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8", "actions/attest-build-provenance@v4"
            )
        )

    def test_attest_job_may_not_use_another_action(self) -> None:
        self.assert_rejected(
            self.WORKFLOW_TEXT.rstrip("\n")
            + "\n\n      - name: Other\n        uses: actions/cache@0000000000000000000000000000000000000000\n"
        )

    def test_attest_job_must_fetch_by_artifact_id_not_name(self) -> None:
        self.assert_rejected(
            self.WORKFLOW_TEXT.replace(
                "          artifact-ids: ${{ needs.sign.outputs.artifact_id }}\n",
                "          name: ${{ needs.resolve.outputs.artifact_name }}\n",
            )
        )


if __name__ == "__main__":
    unittest.main()
