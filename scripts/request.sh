#!/usr/bin/env bash
set -euo pipefail

repo="${BROKER_REPOSITORY:-trsdn/macos-notarization-broker}"
ref="${BROKER_REF:-main}"
app="${1:-}"
tag="${2:-}"
output="${3:-broker-artifacts}"

case "$app" in
  md2loop|openconnect|openwritr|ptionsplus|spacemender|teleprompter) ;;
  *)
    echo "Usage: $0 {md2loop|openconnect|openwritr|ptionsplus|spacemender|teleprompter} vX.Y.Z [output-directory]" >&2
    exit 1
    ;;
esac
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] || {
  echo "Tag must be an exact version tag such as v1.0.2." >&2
  exit 1
}
[[ "$ref" == "main" ]] || {
  echo "The public broker may be dispatched only from main." >&2
  exit 1
}

for tool in gh python3; do
  command -v "$tool" >/dev/null || {
    echo "Required tool not found: $tool" >&2
    exit 1
  }
done
gh auth status >/dev/null

request_id="$(
  python3 -c 'import uuid; print("req-" + uuid.uuid4().hex)'
)"
expected_title="Notarize ${app} ${tag} (${request_id})"
artifact_name="${app}-${tag#v}-${request_id}"

gh workflow run notarize.yml \
  --repo "$repo" \
  --ref "$ref" \
  --field "app=$app" \
  --field "tag=$tag" \
  --field "request_id=$request_id"

run_id=""
for _ in $(seq 1 30); do
  runs_json="$(
    gh run list \
      --repo "$repo" \
      --workflow notarize.yml \
      --event workflow_dispatch \
      --branch "$ref" \
      --limit 30 \
      --json databaseId,displayTitle
  )"
  run_id="$(
    printf '%s' "$runs_json" |
      python3 -c '
import json
import sys

title = sys.argv[1]
for run in json.load(sys.stdin):
    if run.get("displayTitle") == title:
        print(run["databaseId"])
        break
' "$expected_title"
  )"
  [[ -n "$run_id" ]] && break
  sleep 2
done
[[ -n "$run_id" ]] || {
  echo "Could not correlate the dispatched workflow run for request $request_id." >&2
  exit 1
}

gh run watch "$run_id" --repo "$repo" --exit-status

destination="$output/${app}-${tag#v}-${request_id}"
mkdir -p "$destination"
[[ -z "$(find "$destination" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
  echo "Download destination must be empty: $destination" >&2
  exit 1
}
gh run download "$run_id" \
  --repo "$repo" \
  --name "$artifact_name" \
  --dir "$destination"

python3 - "$destination" "$app" "$tag" "$request_id" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
expected_app, expected_tag, expected_request = sys.argv[2:]
provenance_path = root / "provenance.json"
if not provenance_path.is_file():
    raise SystemExit("Downloaded artifact is missing provenance.json")
provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
if provenance.get("profile") != expected_app:
    raise SystemExit("Downloaded artifact profile does not match the request")
if provenance.get("request_id") != expected_request:
    raise SystemExit("Downloaded artifact request ID does not match the request")
source = provenance.get("source", {})
if source.get("tag") != expected_tag:
    raise SystemExit("Downloaded artifact tag does not match the request")
if not re.fullmatch(r"[0-9a-f]{40}", source.get("commit_sha", "")):
    raise SystemExit("Downloaded artifact has no immutable source commit")
for artifact in provenance.get("artifacts", []):
    path = root / artifact["name"]
    if not path.is_file():
        raise SystemExit(f"Downloaded release file is missing: {path.name}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != artifact.get("sha256"):
        raise SystemExit(f"Downloaded release digest mismatch: {path.name}")
print(f"Verified source commit {source['commit_sha']}")
PY

echo "Downloaded and verified notarized artifacts in $destination."
