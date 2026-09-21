#!/usr/bin/env python3
"""Static security checks for the notarization broker repository."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = ROOT / ".github" / "workflows"
WORKFLOW = WORKFLOW_DIR / "notarize.yml"
MIGRATION_WORKFLOW = WORKFLOW_DIR / "migrate-signing-secrets.yml"
LOCAL_WORKFLOW = WORKFLOW_DIR / "notarize-local.yml"
PINNED_ACTION = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}")
PERMISSION_VALUE = re.compile(
    r"^\s+[a-z-]+:\s*(read|write|none|read-all|write-all)\s*$", re.MULTILINE
)
# The complete set of secrets the workflow is allowed to read, named rather than
# counted so that adding one is a deliberate edit here and not an off-by-one.
WORKFLOW_SECRETS = {
    "APPLE_APP_PASSWORD",
    "APPLE_ID",
    "APPLE_TEAM_ID",
    "MACOS_CERTIFICATE",
    "MACOS_CERTIFICATE_PWD",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def workflow_paths() -> list[Path]:
    return sorted(
        path for pattern in ("*.yml", "*.yaml") for path in WORKFLOW_DIR.glob(pattern)
    )


def require_pinned_actions(workflow: str, label: str) -> None:
    for action in re.findall(r"^\s*(?:-\s+)?uses:\s*([^#\s]+)", workflow, re.MULTILINE):
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


ATTEST_PERMISSIONS = {
    "actions": "read",
    "attestations": "write",
    "contents": "read",
    "id-token": "write",
}
ATTEST_ACTIONS = {"actions/download-artifact", "actions/attest-build-provenance"}


def validate_attest_job(workflow: str) -> None:
    """The one job allowed to write, and exactly what it may write.

    Everything before it may not grant a non-read permission at all. The attest job
    gets `attestations` and `id-token` write and nothing else, references no secret
    or environment, runs no shell, and uses only two pinned actions.
    """
    require("\n  attest:\n" in workflow, "the attest job is missing")
    before, block = workflow.split("\n  attest:\n", 1)
    require("\n  sign:\n" in before, "the attest job must come after the sign job")
    for value in PERMISSION_VALUE.findall(before):
        require(value in {"read", "none"}, "a job other than attest grants a non-read permission")
    require(
        "artifact-ids: ${{ needs.sign.outputs.artifact_id }}" in block and "name: ${{ needs" not in block,
        "the attest job must fetch the artifact by the sign job's immutable artifact id, never by name",
    )
    require("secrets." not in block, "the attest job references a secret")
    require("environment:" not in block, "the attest job uses an environment")
    require("\n        run:" not in block and "run: |" not in block, "the attest job runs a shell")
    require(
        "      - resolve" in block and "      - sign" in block,
        "the attest job must need resolve and sign",
    )
    permissions = dict(
        re.findall(r"^      ([a-z-]+):\s*(read|write|none)\s*$", block.split("    steps:")[0], re.MULTILINE)
    )
    require(
        permissions == ATTEST_PERMISSIONS,
        f"the attest job permissions must be exactly {ATTEST_PERMISSIONS}, not {permissions}",
    )
    used = re.findall(r"^\s*(?:-\s+)?uses:\s*([^#\s]+)", block, re.MULTILINE)
    require(used, "the attest job uses no actions")
    for action in used:
        require(PINNED_ACTION.fullmatch(action) is not None, f"attest: action is not pinned: {action}")
        require(action.split("@")[0] in ATTEST_ACTIONS, f"attest: unexpected action {action}")


def validate_notarize_workflow() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    trigger_block = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    require("workflow_dispatch:" in trigger_block, "workflow_dispatch trigger is missing")
    for forbidden in ("pull_request:", "pull_request_target:", "push:", "schedule:"):
        require(forbidden not in trigger_block, f"forbidden trigger present: {forbidden}")
    require("\npermissions: {}\n" in workflow, "top-level permissions must be empty")

    actions = re.findall(r"^\s*(?:-\s+)?uses:\s*([^#\s]+)", workflow, re.MULTILINE)
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

    validate_attest_job(workflow)

    first_secret = workflow.index("secrets.")
    require(first_secret > workflow.index("\n  sign:\n"), "Apple secrets are referenced before sign job")
    referenced = sorted(set(re.findall(r"secrets\.([A-Z0-9_]+)", workflow)))
    require(
        referenced == sorted(WORKFLOW_SECRETS),
        f"unexpected workflow secret references: {', '.join(referenced)}",
    )
    require_no_expression_interpolation(workflow, "notarize.yml")

    authorization_markers = (
        "EXPECTED_BROKER_REPOSITORY_ID",
        "AUTHORIZED_ACTOR_ID",
        '[[ "$REF" == "refs/heads/main" ]]',
        '[[ "$EVENT_NAME" == "workflow_dispatch" ]]',
    )
    for marker in authorization_markers:
        require(marker in workflow, f"authorization gate is missing: {marker}")


def validate_migration_workflow(path: Path) -> None:
    """One narrowly named, protected exception for sealed credential migration."""
    label = path.name
    workflow = path.read_text(encoding="utf-8")
    require("\npermissions: {}\n" in workflow, f"{label}: top-level permissions must be empty")
    for value in PERMISSION_VALUE.findall(workflow):
        require(value in {"read", "none"}, f"{label}: migration may not grant write permissions")
    trigger = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    require(
        re.findall(r"^  ([A-Za-z_]+):", trigger, re.MULTILINE) == ["workflow_dispatch"],
        f"{label}: migration must have only the manual dispatch trigger",
    )
    require(
        not re.search(r"^\s*inputs:", trigger, re.MULTILINE),
        f"{label}: migration must not accept caller-selected recipients or other inputs",
    )
    jobs = workflow.split("\njobs:\n", 1)[1]
    require(
        len(re.findall(r"^  [A-Za-z0-9_-]+:\s*$", jobs, re.MULTILINE)) == 1,
        f"{label}: migration must have exactly one protected job",
    )
    require(
        re.findall(r"^\s*environment:\s*(.+)$", workflow, re.MULTILINE) == ["macos-signing"],
        f"{label}: migration requires the protected macos-signing environment",
    )
    require(
        "\n    environment: macos-signing\n" in jobs,
        f"{label}: the environment must protect the job",
    )
    require(
        set(re.findall(r"secrets\.([A-Z0-9_]+)", workflow)) == WORKFLOW_SECRETS,
        f"{label}: migration must reference exactly the five existing Apple secrets",
    )
    secret_reference = re.compile(r"\$\{\{[^}]*\bsecrets\.")
    secret_lines = [line for line in workflow.splitlines() if secret_reference.search(line)]
    for line in secret_lines:
        require(
            re.fullmatch(
                r"          ([A-Z0-9_]+): \$\{\{ secrets\.\1 \}\}", line
            ) is not None,
            f"{label}: Apple secrets must be passed only through matching step env names",
        )
    secret_steps = [
        step for step in re.split(r"^      - ", workflow, flags=re.MULTILINE)
        if secret_reference.search(step)
    ]
    require(len(secret_steps) == 1, f"{label}: only the sealing step may reference secrets")
    require(
        "python3 scripts/migrate-signing-secrets.py" in secret_steps[0],
        f"{label}: secrets may be consumed only by the broker migration script",
    )
    gate = re.search(r"^    if: >-\n((?:      .+\n)+)", jobs, re.MULTILINE)
    expected_gate = (
        "github.event_name == 'workflow_dispatch' && "
        "github.ref == 'refs/heads/main' && "
        "github.repository == 'trsdn/macos-notarization-broker' && "
        "github.event.repository.id == 1315404585 && "
        "github.actor_id == '24534196'"
    )
    require(
        gate is not None and " ".join(gate.group(1).split()) == expected_gate,
        f"{label}: job-level immutable owner/main authorization is missing",
    )
    require("persist-credentials: false" in workflow, f"{label}: checkout must not persist credentials")
    require("ref: ${{ github.sha }}" in workflow, f"{label}: checkout must pin immutable broker code")
    require(
        not re.search(r"^\s*repository:", workflow, re.MULTILINE),
        f"{label}: migration must not check out an external repository",
    )
    actions = re.findall(r"^\s*(?:-\s+)?uses:\s*([^#\s]+)", workflow, re.MULTILINE)
    require(
        [action.split("@", 1)[0] for action in actions]
        == ["actions/checkout", "actions/upload-artifact"],
        f"{label}: migration must use exactly checkout then ciphertext upload",
    )
    require_pinned_actions(workflow, label)
    require_no_expression_interpolation(workflow, label)
    commands = re.findall(r"^        run: (.+)$", workflow, re.MULTILINE)
    require(len(re.findall(r"^\s*(?:-\s+)?run:", workflow, re.MULTILINE)) == len(commands),
            f"{label}: unexpected command form")
    require(
        commands == [
            "sudo apt-get update -qq && sudo apt-get install -y -qq libsodium23",
            "python3 scripts/migrate-signing-secrets.py",
        ],
        f"{label}: migration may execute only its reviewed library setup and sealing script",
    )
    require(
        "        run: python3 scripts/migrate-signing-secrets.py" in secret_steps[0],
        f"{label}: the secret-consuming step must execute only the sealing script",
    )
    require(
        re.findall(r"^\s*path:\s*(.+)$", workflow, re.MULTILINE) == ["sealed-signing-secrets.json"]
        and "\n          if-no-files-found: error\n" in workflow
        and "\n          retention-days: 1\n" in workflow,
        f"{label}: upload must select only sealed ciphertext with one-day retention",
    )


def validate_local_workflow(path: Path) -> None:
    """Encrypted private handoff has no build job and no public plaintext handoff."""
    label = path.name
    workflow = path.read_text()
    require("\npermissions: {}\n" in workflow, f"{label}: top-level permissions must be empty")
    for value in PERMISSION_VALUE.findall(workflow):
        require(value in {"read", "none"}, f"{label}: write permissions are forbidden")
    trigger = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    require(
        re.findall(r"^  ([A-Za-z_]+):", trigger, re.MULTILINE) == ["workflow_dispatch"],
        f"{label}: only owner manual dispatch is supported",
    )
    input_names = re.findall(r"^      ([a-z_0-9]+):", trigger, re.MULTILINE)
    require(
        len(input_names) == 8 and set(input_names) == {
            "app", "tag", "source_sha", "source_ref_sha", "source_tag_object_sha",
            "archive_sha256", "return_recipient", "request_id",
        },
        f"{label}: only the fixed owner-attestation input contract is allowed",
    )
    jobs = workflow.split("\njobs:\n", 1)[1]
    require(
        re.findall(r"^  ([A-Za-z0-9_-]+):\s*$", jobs, re.MULTILINE) == ["preflight", "sign"],
        f"{label}: only independent preflight and sign jobs are allowed",
    )
    preflight, signing = jobs.split("\n  sign:\n", 1)
    require("secrets." not in workflow.split("\njobs:\n", 1)[0],
            f"{label}: workflow-level secrets are forbidden")
    require("secrets." not in preflight and "environment:" not in preflight,
            f"{label}: preflight may not access credentials or an environment")
    require("\n    environment: macos-signing\n" in signing, f"{label}: protected signing is missing")
    require(re.search(r"^    needs: preflight$", signing, re.MULTILINE) is not None,
            f"{label}: independent preflight is mandatory")
    require(
        set(re.findall(r"secrets\.([A-Z0-9_]+)", signing))
        == WORKFLOW_SECRETS | {"LOCAL_HANDOFF_AGE_IDENTITY"},
        f"{label}: unexpected signing secret references",
    )
    secret_lines = [line for line in workflow.splitlines()
                    if re.search(r"\$\{\{[^}]*\bsecrets\.", line)]
    require(len(secret_lines) == 6, f"{label}: each signing secret must be referenced once")
    for line in secret_lines:
        require(re.fullmatch(r"          ([A-Z0-9_]+): \$\{\{ secrets\.\1 \}\}", line) is not None,
                f"{label}: signing secrets must use matching step-only environment names")
    for section in (preflight, signing):
        gate = re.search(r"^    if: >-\n((?:      .+\n)+)", section, re.MULTILINE)
        expected = (
            "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && "
            "github.repository == 'trsdn/macos-notarization-broker' && "
            "github.event.repository.id == 1315404585 && github.actor_id == '24534196' && "
            "github.run_attempt == 1"
        )
        require(gate is not None and " ".join(gate.group(1).split()) == expected,
                f"{label}: immutable owner/main/first-attempt gate is missing")
    secret_steps = [
        step for step in re.split(r"^      - ", signing, flags=re.MULTILINE)
        if re.search(r"\$\{\{[^}]*\bsecrets\.", step)
    ]
    require(len(secret_steps) == 2, f"{label}: secret access must use two separate steps")
    require(
        set(re.findall(r"secrets\.([A-Z0-9_]+)", secret_steps[0])) == {"LOCAL_HANDOFF_AGE_IDENTITY"}
        and "run: python3 scripts/local_handoff.py sign-prepare" in secret_steps[0],
        f"{label}: decryption/revalidation must precede Apple credentials",
    )
    require(
        set(re.findall(r"secrets\.([A-Z0-9_]+)", secret_steps[1])) == WORKFLOW_SECRETS
        and "run: python3 scripts/local_handoff.py sign-finish" in secret_steps[1],
        f"{label}: Apple credentials may be consumed only by broker signing",
    )
    require(
        re.findall(r"^        run: (.+)$", workflow, re.MULTILINE) == [
            "python3 scripts/local_handoff.py start",
            "python3 scripts/local_handoff.py preflight",
            "rm -rf .local-handoff",
            "python3 scripts/local_handoff.py sign-prepare",
            "python3 scripts/local_handoff.py sign-finish",
            "rm -rf .local-handoff encrypted-input",
        ],
        f"{label}: only the reviewed broker handoff and cleanup commands may execute",
    )
    require(len(re.findall(r"^\s*(?:-\s+)?run:", workflow, re.MULTILINE)) == 6,
            f"{label}: unexpected command form")
    require(
        re.findall(r"^\s*path:\s*(.+)$", workflow, re.MULTILINE) == [
            ".local-handoff/public/challenge.json",
            ".local-handoff/outbound/validated.age",
            "encrypted-input",
            ".local-handoff/outbound/result.age",
        ],
        f"{label}: artifacts may contain only public challenge or encrypted payloads",
    )
    require(
        "artifact-ids: ${{ needs.preflight.outputs.artifact_id }}" in signing
        and "EXPECTED_CIPHERTEXT_SHA256: ${{ needs.preflight.outputs.ciphertext_sha256 }}" in signing
        and "EXPECTED_TREE_SHA256: ${{ needs.preflight.outputs.tree_sha256 }}" in signing,
        f"{label}: immutable encrypted preflight identity and digests are required",
    )
    require(
        workflow.count("ref: ${{ github.sha }}") == 2
        and workflow.count("persist-credentials: false") == 2
        and not re.search(r"^\s*repository:", workflow, re.MULTILINE),
        f"{label}: both jobs must check out only immutable broker code",
    )
    require_pinned_actions(workflow, label)
    require_no_expression_interpolation(workflow, label)
    require(
        [action.split("@", 1)[0] for action in
         re.findall(r"^\s*(?:-\s+)?uses:\s*([^#\s]+)", workflow, re.MULTILINE)]
        == ["actions/checkout", "actions/upload-artifact", "actions/upload-artifact",
            "actions/checkout", "actions/download-artifact", "actions/upload-artifact"],
        f"{label}: only broker checkout and encrypted artifact actions are allowed",
    )


def main() -> int:
    paths = workflow_paths()
    require(WORKFLOW in paths, "notarization workflow is missing")
    validate_notarize_workflow()
    for path in paths:
        if path == MIGRATION_WORKFLOW:
            validate_migration_workflow(path)
        elif path == LOCAL_WORKFLOW:
            validate_local_workflow(path)
        elif path != WORKFLOW:
            validate_supporting_workflow(path)

    print("Static broker security validation passed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, IndexError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
