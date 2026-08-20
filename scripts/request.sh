#!/usr/bin/env bash
set -euo pipefail

repo="${BROKER_REPOSITORY:-trsdn/macos-notarization-broker}"
app="${1:-}"
tag="${2:-}"
output="${3:-broker-artifacts}"

case "$app" in
  md2loop|openwritr|ptionsplus|teleprompter) ;;
  *)
    echo "Usage: $0 {md2loop|openwritr|ptionsplus|teleprompter} vX.Y.Z [output-directory]" >&2
    exit 1
    ;;
esac
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] || {
  echo "Tag must be an exact version tag such as v1.0.2." >&2
  exit 1
}

gh workflow run notarize.yml --repo "$repo" --field "app=$app" --field "tag=$tag"
sleep 3
run_id="$(gh run list --repo "$repo" --workflow notarize.yml --event workflow_dispatch \
  --limit 1 --json databaseId --jq '.[0].databaseId')"
[[ -n "$run_id" ]] || {
  echo "Could not find the dispatched workflow run." >&2
  exit 1
}
gh run watch "$run_id" --repo "$repo" --exit-status
mkdir -p "$output"
gh run download "$run_id" --repo "$repo" --name "${app}-${tag#v}" --dir "$output"
echo "Downloaded notarized artifacts to $output."
