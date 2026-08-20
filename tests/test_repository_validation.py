from __future__ import annotations

import contextlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
