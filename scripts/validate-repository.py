#!/usr/bin/env python3
"""Static security checks for the notarization broker repository."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = ROOT / ".github" / "workflows"
WORKFLOW = WORKFLOW_DIR / "notarize.yml"
PROFILE_FILE = ROOT / "profiles" / "apps.json"
REQUEST_SCRIPT = ROOT / "scripts" / "request.sh"
PINNED_ACTION = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}")
PERMISSION_VALUE = re.compile(
    r"^\s+[a-z-]+:\s*(read|write|none|read-all|write-all)\s*$", re.MULTILINE
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def workflow_paths() -> list[Path]:
    return sorted(
        path for pattern in ("*.yml", "*.yaml") for path in WORKFLOW_DIR.glob(pattern)
    )


def require_pinned_actions(workflow: str, label: str) -> None:
    for action in re.findall(r"^\s*uses:\s*([^#\s]+)", workflow, re.MULTILINE):
        require(
            PINNED_ACTION.fullmatch(action) is not None,
            f"{label}: action is not pinned to a full commit: {action}",
        )


def require_no_expression_interpolation(workflow: str, label: str) -> None:
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
            f"{label}: GitHub expression is interpolated directly into a shell command",
        )


def validate_supporting_workflow(path: Path) -> None:
    """Checks applied to every workflow other than the notarization workflow."""

    label = path.name
    workflow = path.read_text(encoding="utf-8")
    require(
        "\npermissions: {}\n" in workflow,
        f"{label}: top-level permissions must be empty",
    )
    for value in PERMISSION_VALUE.findall(workflow):
        require(
            value in {"read", "none"},
            f"{label}: workflow grants a non-read permission: {value}",
        )
    require(
        "secrets." not in workflow,
        f"{label}: only the notarization workflow may reference secrets",
    )
    require(
        "environment:" not in workflow,
        f"{label}: only the notarization workflow may use a deployment environment",
    )
    require(
        "pull_request_target:" not in workflow,
        f"{label}: pull_request_target exposes a privileged context to untrusted code",
    )
    require_pinned_actions(workflow, label)
    require_no_expression_interpolation(workflow, label)


def validate_notarize_workflow() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    trigger_block = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    require("workflow_dispatch:" in trigger_block, "workflow_dispatch trigger is missing")
    for forbidden in ("pull_request:", "pull_request_target:", "push:", "schedule:"):
        require(forbidden not in trigger_block, f"forbidden trigger present: {forbidden}")
    require("\npermissions: {}\n" in workflow, "top-level permissions must be empty")

    actions = re.findall(r"^\s*uses:\s*([^#\s]+)", workflow, re.MULTILINE)
    require(actions, "workflow does not use any pinned actions")
    require_pinned_actions(workflow, "notarize.yml")

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
    require_no_expression_interpolation(workflow, "notarize.yml")

    authorization_markers = (
        "EXPECTED_BROKER_REPOSITORY_ID",
        "AUTHORIZED_ACTOR_ID",
        '[[ "$REF" == "refs/heads/main" ]]',
        '[[ "$EVENT_NAME" == "workflow_dispatch" ]]',
    )
    for marker in authorization_markers:
        require(marker in workflow, f"authorization gate is missing: {marker}")


def declared_profiles() -> set[str]:
    with PROFILE_FILE.open("r", encoding="utf-8") as handle:
        return set(json.load(handle)["profiles"])


def validate_profile_choices() -> None:
    """Keep every hand-maintained copy of the profile list in step with apps.json.

    The dispatch dropdown and the request client each repeat the profile names.
    A profile missing from either one is silently undispatchable, which is a
    configuration failure rather than a policy failure, so it is caught here
    instead of being left to review.
    """

    profiles = declared_profiles()
    require(profiles, "no profiles are declared")

    workflow = WORKFLOW.read_text(encoding="utf-8")
    options_block = workflow.split("\n        options:\n", 1)[1].split("\n      tag:", 1)[0]
    options = set(re.findall(r"^\s*-\s*([a-z0-9-]+)\s*$", options_block, re.MULTILINE))
    require(
        options == profiles,
        f"notarize.yml app choices do not match apps.json: {sorted(options ^ profiles)}",
    )

    request = REQUEST_SCRIPT.read_text(encoding="utf-8")
    listed = re.findall(
        r"^  ([a-z0-9|-]+)\) ;;$|\{([a-z0-9|-]+)\} vX\.Y\.Z", request, re.MULTILINE
    )
    # Both the case arm and the usage message must be found; a loop over zero
    # matches would otherwise pass this check silently after a reformat.
    require(
        len(listed) == 2,
        f"request.sh no longer exposes a recognisable profile list ({len(listed)} found)",
    )
    for match in listed:
        names = set((match[0] or match[1]).split("|"))
        require(
            names == profiles,
            f"request.sh profile list does not match apps.json: {sorted(names ^ profiles)}",
        )


def main() -> int:
    paths = workflow_paths()
    require(WORKFLOW in paths, "notarization workflow is missing")
    validate_notarize_workflow()
    validate_profile_choices()
    for path in paths:
        if path != WORKFLOW:
            validate_supporting_workflow(path)

    print("Static broker security validation passed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, IndexError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
