#!/usr/bin/env bash
set -euo pipefail
set +x

repo="${BROKER_REPOSITORY:-trsdn/macos-notarization-broker}"
team_id="${APPLE_TEAM_ID:-G69Z5BNY97}"
certificate="${1:-}"
gui_mode=false

if [[ "$certificate" == "--gui" ]]; then
  gui_mode=true
  certificate=""
fi

for tool in base64 gh osascript; do
  command -v "$tool" >/dev/null || {
    echo "Required tool not found: $tool" >&2
    exit 1
  }
done
gh auth status >/dev/null

if [[ "$gui_mode" == true ]]; then
  certificate="$(osascript -e 'POSIX path of (choose file with prompt "Select the Developer ID P12 certificate")')"
  apple_id="$(osascript -e 'text returned of (display dialog "Apple ID:" default answer "" with title "Notarization Broker Setup")')"
  app_password="$(osascript -e 'text returned of (display dialog "Apple app-specific password:" default answer "" with hidden answer with title "Notarization Broker Setup")')"
  certificate_password="$(osascript -e 'text returned of (display dialog "P12 password:" default answer "" with hidden answer with title "Notarization Broker Setup")')"
else
  if [[ -z "$certificate" || ! -f "$certificate" ]]; then
    echo "Usage: $0 /path/to/developer-id.p12 | --gui" >&2
    exit 1
  fi
  read -r -p "Apple ID: " apple_id
  read -r -s -p "Apple app-specific password: " app_password
  printf '\n'
  read -r -s -p "P12 password: " certificate_password
  printf '\n'
fi

[[ -f "$certificate" ]] || {
  echo "Selected P12 certificate does not exist." >&2
  exit 1
}

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
