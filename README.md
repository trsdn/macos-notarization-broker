# macOS notarization broker

[![CI](https://github.com/trsdn/macos-notarization-broker/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/trsdn/macos-notarization-broker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A manual GitHub Actions broker that produces notarized macOS artifacts for a
fixed set of source repositories, without exposing Apple credentials to source
repository code.

## Security design

The workflow runs four isolated jobs:

1. **Resolve** authorizes the request and pins the requested tag to a commit
   SHA.
2. **Build** builds the unsigned app from that commit, with no access to
   signing secrets.
3. **Preflight** validates and repackages the bundle on a fresh secretless
   runner.
4. **Sign** signs, notarizes, staples, and checksums in the protected
   `macos-signing` environment using only broker-owned code.

Step 4 waits for a required reviewer, so a run can sit idle for as long as
GitHub allows a gated run to wait. The bundle handed between steps is retained
for that whole window; approving late is slow, never fatal.

External source scripts never run in the privileged job, action dependencies
are pinned to commit SHAs, and permissions are read-only per job.

See [SECURITY.md](SECURITY.md) for the full model and required repository
rules.

## Setup

Store the Apple values as **environment secrets**, not repository secrets:

```bash
APPLE_TEAM_ID=YOURTEAMID scripts/setup-secrets.sh /path/to/developer-id.p12
```

The script creates the `macos-signing` environment, restricts it to `main`, and
stores the certificate and notarization credentials. The first run may stop
after creating the environment so you can add a required reviewer; rerun it to
finish.

### Apps with restricted entitlements

Some entitlements — installing a system extension, Endpoint Security, a network
extension, DriverKit — are *restricted*: macOS only honours one if the bundle
embeds a provisioning profile that grants it. Nothing in this pipeline notices
a missing profile. Signing succeeds, notarization succeeds, stapling succeeds,
Gatekeeper says "accepted", and the app then dies at launch with a bare
`Launch failed` (`AppleMobileFileIntegrityError -413`, "No matching profile
found"). A profile that claims such an entitlement is therefore rejected here
unless it also points at the profile it needs:

```json
"provisioning_profile": { "path": "provisioning/yourapp.provisionprofile" }
```

The profile lives in this repository, next to the entitlements it belongs to. It
is not a secret: a copy of it ships inside every downloaded app. Keeping it here
rather than in the signing environment means it is reviewable, diffable, and
replaced by a pull request instead of by an unlogged secret update. A declared
path that does not exist fails when the profiles load, before any signing job
has touched a credential.

It must be a **Developer ID** profile from the Apple Developer portal —
Profiles → **+** → Distribution → Developer ID — for the app's App ID, whose
capabilities have to include whatever the restricted entitlement needs. An Xcode
"Mac Team Provisioning Profile" will not do: it is issued for a fixed list of
registered Macs, so it validates on the maintainer's machine and fails on every
other. The broker refuses one.

The app's entitlements must also carry `com.apple.application-identifier`
(`TEAMID.bundle.identifier`) and `com.apple.developer.team-identifier`, because
macOS pairs the signature with the profile through them. Before embedding
anything, the sign job checks the profile's team, expiry, device scope, granted
entitlements, app identifier and signing certificate, so a mismatch or an
expired profile fails the run instead of producing a release nobody can start.

## Run

Use **Actions → Notarize macOS release → Run workflow** from `main`, or:

```bash
scripts/request.sh <app> vX.Y.Z
```

`request.sh` correlates the exact workflow run, downloads only its artifact,
and verifies `provenance.json` plus release digests. Run it without arguments
to list the accepted profiles.

Local signing is intentionally disabled; `scripts/local.sh` dispatches the same
hardened workflow.

## Profiles and outputs

Profile policy is declarative in `profiles/apps.json`, with broker-owned
entitlements and dependency locks under `profiles/`. Validation is strict: a
release that changes its bundle identifier, executable, layout, architecture,
entitlement policy, minimum macOS version, or dependency contract requires a
reviewed profile update.

A profile may declare `nested_executables` to ship a second binary, such as a
privileged launch daemon helper, a CoreAudio HAL plug-in bundle, or a System
Extension. Each entry
names an exact bundle-relative path; anything Mach-O or executable that is not
declared is still rejected, and the signing job works inside-out over digests
the secretless preflight recorded. A profile may also be universal: an entry in
`architectures` names each slice (`arm64`, `x86_64`) the build must produce, and
the preflight verifies the shipped binaries carry exactly those. See
[SECURITY.md](SECURITY.md#nested-executable-code).

Each distributable ships with a `.sha256` file, alongside `provenance.json` and
`preflight-manifest.json` in the workflow artifact.

## Validate changes

Run these from the repository root; CI runs the same checks on every pull
request and on pushes to `main`:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/validate-repository.py
python3 -m py_compile scripts/broker.py scripts/validate-repository.py
bash -n scripts/*.sh
ruby -e 'require "yaml"; YAML.load_file(".github/workflows/notarize.yml")'
```

`python3 -m unittest discover -s tests -v` is the primary test command and needs
only a standard Python 3 installation.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request; it covers
the review rules, the security constraints that must be preserved, and the
dependency update process. Participation is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md#reporting-a-vulnerability).

## License

[MIT](LICENSE). The broker signs only the allowlisted applications in
`profiles/apps.json`; the license covers this repository's code, not those
applications.
