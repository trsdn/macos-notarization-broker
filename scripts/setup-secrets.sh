#!/usr/bin/env bash
set -euo pipefail
set +x

repo="${BROKER_REPOSITORY:-trsdn/macos-notarization-broker}"
environment="${BROKER_ENVIRONMENT:-macos-signing}"
team_id="${APPLE_TEAM_ID:-}"
certificate="${1:-}"
gui_mode=false

if [[ "$certificate" == "--gui" ]]; then
  gui_mode=true
  certificate=""
fi

for tool in base64 gh grep osascript python3; do
  command -v "$tool" >/dev/null || {
    echo "Required tool not found: $tool" >&2
    exit 1
  }
done
gh auth status >/dev/null

default_branch="$(gh api "repos/$repo" --jq .default_branch)"
[[ "$default_branch" == "main" ]] || {
  echo "The broker default branch must be main before configuring signing secrets." >&2
  exit 1
}

if environment_json="$(gh api "repos/$repo/environments/$environment" 2>/dev/null)"; then
  custom_policies="$(
    printf '%s' "$environment_json" |
      python3 -c 'import json, sys; print(str(json.load(sys.stdin).get("deployment_branch_policy", {}).get("custom_branch_policies", False)).lower())'
  )"
  [[ "$custom_policies" == "true" ]] || {
    echo "Existing environment '$environment' must use custom deployment branch policies." >&2
    echo "Update it in repository settings without removing its required reviewers." >&2
    exit 1
  }
else
  gh api \
    --method PUT \
    "repos/$repo/environments/$environment" \
    -F wait_timer=0 \
    -F prevent_self_review=false \
    -F 'deployment_branch_policy[protected_branches]=false' \
    -F 'deployment_branch_policy[custom_branch_policies]=true' \
    >/dev/null
fi

policy_exists="$(
  gh api "repos/$repo/environments/$environment/deployment-branch-policies" \
    --jq '.branch_policies[] | select(.name == "main" and .type == "branch") | .id' |
    head -n 1
)"
if [[ -z "$policy_exists" ]]; then
  gh api \
    --method POST \
    "repos/$repo/environments/$environment/deployment-branch-policies" \
    -f name=main \
    -f type=branch \
    >/dev/null
fi

environment_json="$(gh api "repos/$repo/environments/$environment")"
reviewer_count="$(
  printf '%s' "$environment_json" |
    python3 -c '
import json
import sys

environment = json.load(sys.stdin)
count = 0
for rule in environment.get("protection_rules", []):
    if rule.get("type") == "required_reviewers":
        count += len(rule.get("reviewers", []))
print(count)
'
)"
[[ "$reviewer_count" -gt 0 ]] || {
  cat >&2 <<EOF
The '$environment' environment has no required reviewer.
Configure at least one reviewer in repository settings, then rerun this script.
No Apple credentials were stored.
EOF
  exit 1
}

if [[ "$gui_mode" == true ]]; then
  certificate="$(osascript -e 'POSIX path of (choose file with prompt "Select the Developer ID P12 certificate")')"
  apple_id="$(osascript -e 'text returned of (display dialog "Apple ID:" default answer "" with title "Notarization Broker Setup")')"
  app_password="$(osascript -e 'text returned of (display dialog "Apple app-specific password:" default answer "" with hidden answer with title "Notarization Broker Setup")')"
  certificate_password="$(osascript -e 'text returned of (display dialog "P12 password:" default answer "" with hidden answer with title "Notarization Broker Setup")')"
  if [[ -z "$team_id" ]]; then
    team_id="$(osascript -e 'text returned of (display dialog "Apple Team ID:" default answer "" with title "Notarization Broker Setup")')"
  fi
else
  if [[ -z "$certificate" || ! -f "$certificate" ]]; then
    echo "Usage: APPLE_TEAM_ID=TEAMID $0 /path/to/developer-id.p12 | --gui" >&2
    exit 1
  fi
  read -r -p "Apple ID: " apple_id
  read -r -s -p "Apple app-specific password: " app_password
  printf '\n'
  read -r -s -p "P12 password: " certificate_password
  printf '\n'
  if [[ -z "$team_id" ]]; then
    read -r -p "Apple Team ID: " team_id
  fi
fi

[[ -f "$certificate" ]] || {
  echo "Selected P12 certificate does not exist." >&2
  exit 1
}
[[ "$team_id" =~ ^[A-Z0-9]{10}$ ]] || {
  echo "Apple Team ID must be exactly 10 uppercase letters or digits." >&2
  exit 1
}

cleanup() {
  unset apple_id app_password certificate_password encoded_certificate
}
trap cleanup EXIT

encoded_certificate="$(base64 < "$certificate" | tr -d '\n')"
printf '%s' "$encoded_certificate" |
  gh secret set MACOS_CERTIFICATE --repo "$repo" --env "$environment"
printf '%s' "$certificate_password" |
  gh secret set MACOS_CERTIFICATE_PWD --repo "$repo" --env "$environment"
printf '%s' "$apple_id" |
  gh secret set APPLE_ID --repo "$repo" --env "$environment"
printf '%s' "$team_id" |
  gh secret set APPLE_TEAM_ID --repo "$repo" --env "$environment"
printf '%s' "$app_password" |
  gh secret set APPLE_APP_PASSWORD --repo "$repo" --env "$environment"

repository_secrets="$(gh secret list --repo "$repo" --json name --jq '.[].name')"
for secret_name in \
  MACOS_CERTIFICATE \
  MACOS_CERTIFICATE_PWD \
  APPLE_ID \
  APPLE_TEAM_ID \
  APPLE_APP_PASSWORD; do
  if printf '%s\n' "$repository_secrets" | grep -Fxq "$secret_name"; then
    gh secret delete "$secret_name" --repo "$repo"
    echo "Removed obsolete repository-level secret: $secret_name"
  fi
done

cat <<EOF
Configured notarization secrets in the '$environment' environment for $repo.

Repository-level copies were removed. Protect main as described in SECURITY.md
before publishing the repository.
EOF
