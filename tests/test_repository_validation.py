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


class ProfileChoiceConsistencyTests(unittest.TestCase):
    """The profile list is repeated by hand in three files; keep them in step."""

    def run_with(self, *, workflow: str | None = None, request: str | None = None) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            patches = {}
            if workflow is not None:
                path = root / "notarize.yml"
                path.write_text(workflow, encoding="utf-8")
                patches["WORKFLOW"] = path
            if request is not None:
                path = root / "request.sh"
                path.write_text(request, encoding="utf-8")
                patches["REQUEST_SCRIPT"] = path
            with contextlib.ExitStack() as stack:
                for name, value in patches.items():
                    stack.enter_context(mock.patch.object(validator, name, value))
                validator.validate_profile_choices()

    def test_committed_lists_agree(self) -> None:
        validator.validate_profile_choices()

    def test_profile_missing_from_the_dispatch_dropdown_is_rejected(self) -> None:
        workflow = validator.WORKFLOW.read_text(encoding="utf-8")
        with self.assertRaises(AssertionError):
            self.run_with(workflow=workflow.replace("          - spacemender\n", ""))

    def test_unknown_profile_in_the_dispatch_dropdown_is_rejected(self) -> None:
        workflow = validator.WORKFLOW.read_text(encoding="utf-8")
        with self.assertRaises(AssertionError):
            self.run_with(
                workflow=workflow.replace(
                    "          - spacemender\n",
                    "          - spacemender\n          - not-a-profile\n",
                )
            )

    def test_profile_missing_from_the_request_client_is_rejected(self) -> None:
        request = validator.REQUEST_SCRIPT.read_text(encoding="utf-8")
        with self.assertRaises(AssertionError):
            self.run_with(request=request.replace("spacemender|", ""))

    def test_unrecognisable_request_client_is_rejected_rather_than_skipped(self) -> None:
        with self.assertRaises(AssertionError):
            self.run_with(request="#!/usr/bin/env bash\necho hello\n")


if __name__ == "__main__":
    unittest.main()
