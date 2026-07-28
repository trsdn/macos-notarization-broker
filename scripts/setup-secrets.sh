#!/usr/bin/env bash
set -euo pipefail
set +x

repo="${BROKER_REPOSITORY:-trsdn/macos-notarization-broker}"
team_id="${APPLE_TEAM_ID:-G69Z5BNY97}"
certificate="${1:-}"

if [[ -z "$certificate" || ! -f "$certificate" ]]; then
  echo "Usage: $0 /path/to/developer-id.p12" >&2
  exit 1
fi

for tool in base64 gh; do
  command -v "$tool" >/dev/null || {
    echo "Required tool not found: $tool" >&2
    exit 1
  }
done
gh auth status >/dev/null

read -r -p "Apple ID: " apple_id
read -r -s -p "Apple app-specific password: " app_password
printf '\n'
read -r -s -p "P12 password: " certificate_password
printf '\n'

cleanup() {
  unset apple_id app_password certificate_password encoded_certificate
}
trap cleanup EXIT

encoded_certificate="$(base64 < "$certificate" | tr -d '\n')"
printf '%s' "$encoded_certificate" | gh secret set MACOS_CERTIFICATE --repo "$repo"
printf '%s' "$certificate_password" | gh secret set MACOS_CERTIFICATE_PWD --repo "$repo"
printf '%s' "$apple_id" | gh secret set APPLE_ID --repo "$repo"
printf '%s' "$team_id" | gh secret set APPLE_TEAM_ID --repo "$repo"
printf '%s' "$app_password" | gh secret set APPLE_APP_PASSWORD --repo "$repo"

echo "Configured the five notarization secrets in $repo."
