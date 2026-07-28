#!/usr/bin/env bash
set -euo pipefail

app="${1:-}"
tag="${2:-}"
output="${3:-}"
notary_profile="${NOTARY_PROFILE:-OpenWritr}"
team_id="${APPLE_TEAM_ID:-G69Z5BNY97}"

case "$app" in
  md2loop) repository="trsdn/md2loop" ;;
  openwritr) repository="trsdn/OpenWritr" ;;
  ptionsplus) repository="trsdn/PtionsPlus" ;;
  *)
    echo "Usage: $0 {md2loop|openwritr|ptionsplus} vX.Y.Z [output-directory]" >&2
    exit 1
    ;;
esac

[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] || {
  echo "Tag must be an exact version tag such as v1.0.2." >&2
  exit 1
}
[[ "$(uname -s)" == "Darwin" ]] || {
  echo "Local signing and notarization requires macOS." >&2
  exit 1
}

for tool in codesign git hdiutil security shasum xcrun; do
  command -v "$tool" >/dev/null || {
    echo "Required tool not found: $tool" >&2
    exit 1
  }
done
xcrun --find notarytool >/dev/null
xcrun --find stapler >/dev/null

identity="$(
  security find-identity -v -p codesigning |
    awk -F'"' '/Developer ID Application/ { print $2; exit }'
)"
[[ -n "$identity" ]] || {
  echo "No Developer ID Application identity is installed." >&2
  exit 1
}

version="${tag#v}"
if [[ -z "$output" ]]; then
  output="$PWD/broker-artifacts/${app}-${version}"
elif [[ "$output" != /* ]]; then
  output="$PWD/$output"
fi
mkdir -p "$output"
output="$(cd "$output" && pwd -P)"
[[ -z "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
  echo "Output directory must be empty: $output" >&2
  exit 1
}

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/macos-notarization-broker.XXXXXX")"
cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

source_dir="$work_dir/source"
git clone --quiet --depth 1 --branch "$tag" \
  "https://github.com/${repository}.git" "$source_dir"
[[ "$(git -C "$source_dir" describe --tags --exact-match HEAD)" == "$tag" ]] || {
  echo "Cloned source is not the exact requested tag." >&2
  exit 1
}

export RELEASE_ENV_FILE=/dev/null
export NOTARY_PROFILE="$notary_profile"
export CODE_SIGN_IDENTITY="$identity"
export OPENWRITR_SIGNING_IDENTITY="$identity"
export TEAM_ID="$team_id"
export APPLE_TEAM_ID="$team_id"
export RELEASE_TAG="$tag"
export RELEASE_VERSION="$version"
export BUILD_NUMBER="${BUILD_NUMBER:-$(date -u +%Y%m%d%H%M)}"
# SwiftPM uses temporary bare repositories while resolving dependencies.
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=safe.bareRepository
export GIT_CONFIG_VALUE_0=all

cd "$source_dir"
chmod +x scripts/*.sh
case "$app" in
  md2loop)
    command -v xcodegen >/dev/null || {
      echo "xcodegen is required for md2loop." >&2
      exit 1
    }
    DMG_PATH="dist/md2loop-${version}-macos.dmg" scripts/release_macos.sh
    DMG_PATH="dist/md2loop-${version}-macos.dmg" scripts/verify_release_dmg.sh
    cp "dist/md2loop-${version}-macos.dmg"{,.sha256} "$output/"
    ;;
  openwritr)
    scripts/release_macos.sh "$tag"
    cp "dist/OpenWritr-v${version}-macOS-arm64."{zip,zip.sha256,dmg,dmg.sha256} "$output/"
    ;;
  ptionsplus)
    scripts/sign-release.sh
    scripts/notarize.sh
    cp "dist/Ptions+.zip" "dist/Ptions+.dmg" "dist/Ptions+.dmg.sha256" "$output/"
    ;;
esac

echo "Local notarized artifacts are in $output."
