#!/usr/bin/env python3
"""Static security checks for the notarization broker repository."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "notarize.yml"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    trigger_block = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    require("workflow_dispatch:" in trigger_block, "workflow_dispatch trigger is missing")
    for forbidden in ("pull_request:", "pull_request_target:", "push:", "schedule:"):
        require(forbidden not in trigger_block, f"forbidden trigger present: {forbidden}")
    require("\npermissions: {}\n" in workflow, "top-level permissions must be empty")

    actions = re.findall(r"^\s*uses:\s*([^#\s]+)", workflow, re.MULTILINE)
    require(actions, "workflow does not use any pinned actions")
    for action in actions:
        require(
            re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}", action) is not None,
            f"action is not pinned to a full commit: {action}",
        )

    build_block = workflow.split("\n  build:\n", 1)[1].split("\n  preflight:\n", 1)[0]
    require("secrets." not in build_block, "untrusted build job references secrets")
    require("\n    environment:" not in build_block, "untrusted build job uses an environment")
    require(
        'fetch --no-tags --depth=1 origin "$SOURCE_SHA"' in build_block,
        "external source is not fetched by immutable SHA",
    )
    require(
        'SOURCE_SHA: ${{ needs.resolve.outputs.commit_sha }}' in build_block
        and '--commit-sha "$SOURCE_SHA"' in build_block,
        "broker build does not verify the immutable source SHA",
    )

    preflight_block = workflow.split("\n  preflight:\n", 1)[1].split("\n  sign:\n", 1)[0]
    require("secrets." not in preflight_block, "secretless preflight job references secrets")
    require(
        "validate identity and bundle structure".lower() in preflight_block.lower(),
        "preflight validation step is missing",
    )
    for name, block in (("build", build_block), ("preflight", preflight_block)):
        require(
            "APPLE_TEAM_ID" not in block,
            f"{name} job references the Apple Team ID secret; declare team_id in the profile instead",
        )

    sign_block = workflow.split("\n  sign:\n", 1)[1]
    require("environment: macos-signing" in sign_block, "signing environment is missing")
    require("Revalidate before certificate import" in sign_block, "pre-secret validation is missing")
    require("Confirm tag has not moved" in sign_block, "tag movement check is missing")
    require("source/scripts/" not in sign_block, "privileged job executes source repository scripts")
    require("source/build-app.sh" not in sign_block, "privileged job executes source build scripts")
    require("repository: ${{ needs.resolve.outputs.repository }}" not in sign_block, "privileged job checks out source")

    first_secret = workflow.index("secrets.")
    require(first_secret > workflow.index("\n  sign:\n"), "Apple secrets are referenced before sign job")
    require(workflow.count("secrets.") == 5, "unexpected workflow secret reference count")
    lines = workflow.splitlines()
    for index, line in enumerate(lines):
        if line.strip() != "run: |":
            continue
        run_indent = len(line) - len(line.lstrip())
        command_lines: list[str] = []
        for command_line in lines[index + 1 :]:
            if command_line.strip() and len(command_line) - len(command_line.lstrip()) <= run_indent:
                break
            command_lines.append(command_line)
        require(
            "${{" not in "\n".join(command_lines),
            "GitHub expression is interpolated directly into a shell command",
        )

    authorization_markers = (
        "EXPECTED_BROKER_REPOSITORY_ID",
        "AUTHORIZED_ACTOR_ID",
        '[[ "$REF" == "refs/heads/main" ]]',
        '[[ "$EVENT_NAME" == "workflow_dispatch" ]]',
    )
    for marker in authorization_markers:
        require(marker in workflow, f"authorization gate is missing: {marker}")

    print("Static broker security validation passed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, IndexError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
