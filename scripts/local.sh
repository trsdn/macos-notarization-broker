#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

cat >&2 <<'EOF'
Direct local signing is intentionally disabled.

Running untrusted repository build code on a Mac that has a Developer ID
certificate or notarytool credentials would recreate the broker's original
privilege-boundary vulnerability. This command now dispatches the hardened
GitHub Actions workflow instead.
EOF

exec "$script_dir/request.sh" "$@"
