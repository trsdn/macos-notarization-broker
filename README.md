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

Step 4 runs unattended: `macos-signing` has no required reviewer (see
[SECURITY.md](SECURITY.md) for why that's still safe for a sole maintainer).
If a second trusted maintainer joins, reconsider adding one back.

External source scripts never run in the privileged job, action dependencies
are pinned to commit SHAs, and permissions are read-only per job, with one exception:
the `attest` job, which may write only build attestations (see
[SECURITY.md](SECURITY.md#build-attestation)).

Artifacts are attested by default. A profile may set `attest: false` only on a
reviewed artifact exception; a `copy_of` alias must use the same policy as its
byte-identical source, and every profile must retain at least one attested
artifact. OpenWritr is the deliberate exception: its ZIP is attested, but its
versioned DMG and updater alias are not. An installed OpenWritr version can
crash while checking an update if an attestation exists for that DMG digest
([trsdn/OpenWritr#31](https://github.com/trsdn/OpenWritr/issues/31)).

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

To make publishing part of the same command, add `--publish`:

```bash
scripts/request.sh <app> vX.Y.Z --publish
```

After verification it uploads every file that `provenance.json` lists, with its
`.sha256`, plus `provenance.json` and `preflight-manifest.json`, to the release
for that tag in the profile's source repository. If there is no release yet, it
creates one from the tag (`--verify-tag`), with notes extracted from the source
repository's `CHANGELOG.md` entry for exactly that version — required for
every profile; the publish fails if the file is missing, the entry is missing
or empty, or the entry is still sitting under `## Unreleased`. This is the
[trsdn Repository Quality Standard](https://github.com/trsdn/.github/blob/main/docs/repository-quality-standard.md)'s
`R07` gate (see [decision 0010](https://github.com/trsdn/.github/blob/main/docs/decisions/0010-release-notes-come-from-the-changelog.md)),
reproduced here rather than adopted as trsdn/.github's standalone reference
workflow, since a release here never builds or signs inside the source
repository's own CI. The upload uses the caller's `gh` credentials; the
workflow itself never writes to a source repository.

A profile artifact may set `copy_of` to the name of an earlier artifact of the
same type. The signed file is then published a second time under the new name,
byte for byte, and provenance covers both. In-app updaters need this:
[AppUpdater](https://github.com/mxcl/AppUpdater) only accepts an asset named
exactly `<Repository>-<version>.dmg`.

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

A profile may also declare one source-committed application icon:

```json
"app_icon": "Resources/AppIcon.icns"
```

The value is a repository-relative path inside the source checkout. It is
optional — a profile that omits it ships no icon, exactly as before — and it
exists because an adapter that assembles the bundle itself, rather than
inheriting one from an Xcode build, otherwise leaves the source's
`CFBundleIconFile` pointing at a file nobody copied, and the release shows a
generic icon. The icon is copied into `Contents/Resources` in the untrusted
build job, before the secretless preflight sees the bundle, so it is policed
like every other resource there. The declaration itself is checked hard: the
path must be relative, free of `..`, inside the checkout after resolution, a
regular file rather than a link, a directory or a device, a real `.icns` by its
magic and not merely by its name, no larger than 5 MiB, and named exactly what
the shipped `Info.plist` asks for in `CFBundleIconFile` (with or without the
extension, both of which macOS accepts). Anything else fails the build.

Each distributable ships with a `.sha256` file, alongside `provenance.json` and
`preflight-manifest.json` in the workflow artifact.

### Subvocal Full and Light (encrypted local builds)

The prepared `subvocal` and `subvocal-light` profiles describe Apple Silicon,
macOS 15+ releases. They preserve the download names `Subvocal.dmg` and
`SubvocalLight.dmg`, with additional versioned
`Subvocal-v{version}-macOS-arm64.zip` and
`SubvocalLight-v{version}-macOS-arm64.zip` archives.

Their source repository stays private. `notarize.yml` intentionally rejects
these profiles before fetching source or building. Use the separate
`notarize-local.yml` encrypted handoff below. Do not add a source PAT to the
public workflow or change repository visibility.

The broker-owned build adapter runs no source packaging scripts. Local handoff
accepts owner-built unsigned apps subject to the same bundle policy. The source
and packaging contract is:

- Swift 6.2+ and `Subvocal/Package.swift`, products `Subvocal` / `SubvocalLight`.
- `Subvocal/Package.resolved` must exactly match the JSON content of
  `profiles/locks/subvocal-Package.resolved`, including immutable revisions.
  SwiftPM uses `--only-use-versions-from-resolved-file`; a lock change requires
  broker review, even for the branch-based OutlookAX dependency.
  InstrumentWorkshopKit (`design-system`) is pinned to 1.5.1 at
  `9f58bdba169bc0013dd8b9ec80b85f65325ac678`; the other six pins are unchanged.
- Source plists at `Subvocal/Sources/Subvocal/Info.plist` and
  `Subvocal/Sources/SubvocalLightApp/Info.plist` already carry the release version
  (both version keys), flavor identity, privacy descriptions, and `15.0`
  deployment target. Full retains `LSUIElement=true`, Light `false`.
- The icon is `Subvocal/Sources/Subvocal/Assets/AppIcon.icns`. Both flavors
  include exactly the declared SwiftPM resource bundles
  `Subvocal_SubvocalKit.bundle`, `PLCrashReporter_CrashReporter.bundle`, and
  `InstrumentWorkshopKit_InstrumentWorkshopKit.bundle` under `Contents/Resources`.
  The kit bundle contains only `Resources/canonical-workflow-fixture.json`,
  pinned by SHA-256, with no `Info.plist`. Extra files or directories are rejected.
  `Contents/Resources/InstrumentWorkshopKit-LICENSE` is also required and pinned
  by SHA-256 to the dependency's root `LICENSE`. The adapter copies that license
  from `.build/checkouts/design-system/LICENSE`. No nested executable or
  framework is authorized.
- Signing grants only microphone input. No provisioning profile or
  `keychain-access-groups` entitlement is requested. The
  `SubvocalArtifactKeyAccessGroup` Info.plist key is rejected in preflight;
  shared protected artifacts remain unavailable, while the app can launch.

No source-side signing environment variables are needed or supported.
`PROVISIONING_PROFILE` is not read. Enabling protected artifacts later requires
a reviewed provisioning/entitlement/metadata policy for both App IDs.
### Configure encrypted local handoff

The owner generates an age X25519 identity locally, stores it as
`LOCAL_HANDOFF_AGE_IDENTITY` **only in the protected `macos-signing`
environment**, and puts its public `age1...` recipient in
`profiles/local-handoff.json` through broker review. An empty recipient fails
closed. Never commit the private identity. The five Apple secrets must also be
environment-scoped before dispatch.

The helper downloads age **v1.3.2** only from the upstream release, verifies its
platform-specific SHA-256 pin, and extracts only the two regular executable
files. It does not use a system age binary, shell plugins, or arbitrary
recipients files.

After the broker changes are reviewed and merged, the local broker checkout
must be clean and at the exact remote `main` commit. The source checkout must
be clean, at the release tag's commit, and the same tag must already exist in
the private GitHub repository. The local helper checks immutable source
identity, both lightweight/annotated tags, and the broker-pinned package lock.

```bash
scripts/request-local.sh subvocal v2.0.0 \
  --source /path/to/private-checkout \
  --app-bundle "/path/to/private-checkout/dist/Subvocal.app"

scripts/request-local.sh subvocal-light v2.0.0 \
  --source /path/to/private-checkout \
  --app-bundle "/path/to/private-checkout/dist/Subvocal Light.app"
```

The helper validates each unsigned app locally before dispatch. All three declared
resource bundles must be packaged; a binary-only app is rejected. It stages a
private copy and adds owner-write permission to resource files/directories
(SwiftPM's read-only privacy manifest otherwise prevents `xattr` sanitation),
and to the required license file.
Executable bits are preserved and still rejected; the supplied app is unchanged.
It creates
private local state under `.local-handoff-requests/`, with a one-request return
identity. Keep that state until results have been received.

The workflow's independent preflight creates an ephemeral recipient and
publishes a public, run-bound challenge. The local helper verifies the broker
commit, owner, workflow, attempt, profile digest and request before sending
anything. It then uploads only ciphertext to the broker's `local-handoffs`
prerelease (created automatically by the local owner if absent). Existing
local `gh` authentication performs this upload; no token is sent to a runner.
The helper returns the run ID and exact `--resume` command:

```bash
scripts/request-local.sh --resume .local-handoff-requests/local-REQUEST/state.json
```

Review and approve `macos-signing` separately. Resume only after the run
succeeds; the helper rechecks the private source tag, decrypts the results,
verifies provenance and artifact hashes, and deletes the return identity.
Only then publish the returned assets to the **private** application release.
This tool neither approves deployments nor publishes an application release.

Preflight has no environment or repository secrets and never compiles or runs
submitted code. It decrypts on its disposable runner, verifies the committed
input SHA-256, applies the normal bundle validation, and encrypts validated
output to the reviewed signing recipient. A separate protected signing runner
downloads the exact artifact ID, verifies its digest, decrypts and revalidates
before Apple credentials are available to the signing step. All final output
is encrypted to the local return recipient. Public artifacts contain only the
challenge and encrypted payloads; private diagnostics are discarded, not logged.

Provenance explicitly says **`owner-attested-local-build`**. This records the
owner's assertion that the submitted bytes came from the given source commit;
it is not a claim that the broker compiled or independently queried the private
source. Source scripts, credentials, source archives and compilation logs are
never uploaded. Local tag checks supplement, but do not replace, owner approval.
Re-running a workflow is rejected; start a fresh request with a fresh recipient.
The local helper must deliver ciphertext within ten minutes of the challenge.
Encrypted workflow payloads are retained for 30 days; ciphertext staging
release assets may be deleted by the owner after successful receipt.

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
