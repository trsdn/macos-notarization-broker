# AGENTS.md

Guidance for AI coding agents working in this repository.

This repository holds privileged macOS code-signing/notarization logic shared
by every app in this account. Treat it with more caution than an application
repository: a subtle mistake here doesn't break one app, it can silently
weaken the signing pipeline for all of them.

## Build & validate

**Run the full check set before proposing any change:**

```bash
python3 -m unittest discover -s tests -v
python3 scripts/validate-repository.py
python3 -m py_compile scripts/broker.py scripts/validate-repository.py
bash -n scripts/*.sh
ruby -e 'require "yaml"; YAML.load_file(".github/workflows/notarize.yml")'
```

This is [`CONTRIBUTING.md`](CONTRIBUTING.md)'s own list; CI runs the same
commands. It needs only a standard Python 3 installation — no third-party
packages, no network access, no Apple tooling.

`python3 -m unittest discover -s tests -v` is the primary test command
(193 tests as of this writing). `scripts/validate-repository.py` is a static
policy checker — it reads workflow/profile files and enforces most of
`CONTRIBUTING.md`'s "must preserve" list mechanically, but it does **not**
check live GitHub settings (branch protection, environment reviewers): those
have to be verified with `gh api`, separately, if a change claims to affect
them.

There is no build step and nothing to run manually beyond the above: this
repository ships automation, not a product with its own release process.

## Forbidden and high-risk operations

**Never, under any circumstances** (from `CONTRIBUTING.md`'s "Security
constraints that must be preserved" — read that section in full before
touching `scripts/broker.py`, a workflow, or a profile):

- Replace the dispatch gate's immutable numeric identity checks
  (`EXPECTED_BROKER_REPOSITORY_ID`, `AUTHORIZED_ACTOR_ID`) with mutable
  login-name checks.
- Add a shell fragment, hook, secret name, or source-controlled entitlement
  file to `profiles/apps.json` — profiles stay declarative and allowlisted.
- Let Apple secret use leak outside the protected `sign` job, or add a
  secret, an environment, or a write permission to any other job/workflow.
  **The one exception is the `attest` job in `notarize.yml`**: it may have
  `attestations: write` and `id-token: write` (plus `actions: read` and
  `contents: read`) and nothing else, no secret, no environment, no shell, and it
  fetches the notarized artifact by the `sign` job's immutable artifact id.
  `scripts/validate-repository.py` enforces exactly that and rejects every other
  job with a non-read permission.
- Weaken a workflow's `permissions:` block, or drop a full-commit-SHA pin on
  a `uses:` reference.
- Let untrusted source-repository code run in the privileged signing job.
  The **Build** job builds untrusted source with no secrets; only
  **Sign** (protected `macos-signing` environment, broker-owned code only)
  ever touches Apple credentials.
- Add or attach Apple credentials, certificates, provisioning profiles, or
  private workflow logs to an issue, PR, or commit.
- Treat `scripts/migrate-signing-secrets.yml` as a template for anything
  else — it is a one-time, explicitly exempted, owner-ID/`main`-gated
  credential migration path, not a pattern to reuse.

**Ask before doing:**

- Changing anything about the `macos-signing` environment's protection
  rules, or `main`'s branch ruleset — these are the actual security
  boundary this repository has (see `SECURITY.md`'s "Required repository
  settings"), and a change here needs the same PR-reviewed, auditable path
  the ruleset itself requires for everything else.
- Onboarding a new application profile or adapter — get the shape right
  once, since sibling profiles copy whatever pattern exists.
- Publishing a release, or running `scripts/request.sh ... --publish`
  against a real profile — that produces a real, public, signed artifact.

## Architecture

Four isolated jobs per notarization request (`notarize.yml`):

```text
Resolve  → Build (untrusted, no secrets) → Preflight (secretless,      → Sign (protected macos-signing
authorizes  builds the unsigned app from    fresh runner: validates       environment, broker-owned code
the request,  the pinned commit              and repackages the bundle)   only: signs, notarizes, staples)
pins tag→commit SHA
```

Source repositories and their build-time dependencies are always untrusted;
only `scripts/broker.py`'s own code runs with signing privileges, and only in
the last job.

**Adapter taxonomy** (`profiles/apps.json`, one profile per app, dispatched by
`build_adapter`):

- **xcode** — `xcodebuild`-driven (`md2loop`, `ptionsplus`, `spacemender`,
  `openlens`, `better-kampfinsel`, `printfilemanager`, `threemfquicklook`).
  `team_id` is passed as `DEVELOPMENT_TEAM`; it's a declarative identifier,
  not a secret.
- **swiftpm** — `swift build`-driven. `assemble_menu_bar_swiftpm` is shared
  by menu-bar apps that link AppUpdater and enforce `LSUIElement`
  (`opendefendrwatchr`, `openzombr`, `openzonr`), and copies the icon named by
  the optional `app_icon` profile field when one is declared — a SwiftPM build
  ships no icon otherwise, so an app whose `Info.plist` names one would release
  with a generic icon; `assemble_openpromptr` is its own
  adapter for a regular windowed app whose `Info.plist` lives at
  `Config/Info.plist` rather than `Sources/<product>/Info.plist`;
  `assemble_openwritr`/`assemble_openswitchr` are simpler, dependency-light
  variants; `subvocal`/`subvocal-light` add InstrumentWorkshopKit resource
  verification with per-file digests.
- **make** — `openconnct`, Makefile-driven; AppUpdater is linked in as
  object files, so it has no resource bundle to declare.

**Local-handoff path** (`notarize-local.yml` + `scripts/request-local.sh` +
`scripts/local_handoff.py`): for `subvocal`/`subvocal-light`, whose source is
private. The owner encrypts a pre-built app to a broker-side ephemeral
recipient with age (X25519); the broker validates and signs it without ever
checking out the private source; results encrypt back to the owner.
`scripts/age_tool.py` pins the exact age binary by SHA-256 rather than
trusting whatever `age` is on `PATH`. **This path's provenance says
`owner-attested-local-build`, not independently-built provenance — never
conflate the two when reasoning about what a given release actually proves.**
Local signing itself (skipping the workflow entirely) is intentionally
disabled; `scripts/local.sh` still dispatches the same hardened workflow.

## Non-negotiable design constraints

- **Restricted entitlements fail silently, long after signing.** Installing
  a system extension, Endpoint Security, a network extension, or DriverKit
  requires a matching provisioning profile — without one, signing succeeds,
  notarization succeeds, stapling succeeds, Gatekeeper says "accepted", and
  the app dies at launch with a bare `Launch failed`
  (`AppleMobileFileIntegrityError -413`, "No matching profile found"). The
  broker rejects a profile claiming such an entitlement unless it also
  declares `provisioning_profile`, checking team/expiry/device
  scope/entitlements/app identifier/certificate before any signing touches
  it — but only for entitlements it recognizes as restricted. Adding a new
  kind of restricted entitlement to a profile means checking whether that
  validation needs to know about it too.
- **`copy_of` artifacts are copied, never rebuilt.** A profile artifact can
  name an earlier one as `copy_of`; the broker copies the already-signed,
  already-verified bytes under the new name inside the signing job, with a
  digest re-check, rather than building or notarizing twice. In-app updaters
  need this: AppUpdater only accepts an asset named exactly
  `<Repository>-<version>.dmg`. Because attestations are digest-based, a copy
  must also use the same declarative `attest` policy as its source. Artifacts
  default to attested and every profile must retain at least one attested
  artifact.
- **`casefold()`, not `lower()`, for filesystem-path matching.** Launch
  daemon/agent directory matching folds case with `casefold()` because
  `lower()` leaves `U+017F LONG S` unchanged on APFS's Unicode case folding —
  a check built on `lower()` could be bypassed by a specially-spelled
  directory name that looks identical to the eye.
- **`gh release create --notes-from-tag` cannot be combined with `--repo`.**
  It reads the tag's annotation from a *local* git checkout, which
  `scripts/request.sh` never has — it only ever holds a checkout of this
  repository, never of a profile's source repository. Found the hard way
  cutting `trsdn/OpenPromptr`'s actual first release — the flag combination
  fails for every profile, not just that one. This is why release notes
  aren't sourced from the tag at all anymore — see the next point.
- **Release notes come from `CHANGELOG.md`, not the tag, and this is
  mandatory for every profile.** `request.sh --publish` fetches the source
  repository's `CHANGELOG.md` at the tag through the API and extracts the
  entry for exactly that version, failing the release if the file is
  missing, the entry is missing or empty, or the entry is still sitting
  under `## Unreleased` — the `R07` gate from the
  [trsdn Repository Quality Standard](https://github.com/trsdn/.github/blob/main/docs/repository-quality-standard.md)
  (see [decision 0010](https://github.com/trsdn/.github/blob/main/docs/decisions/0010-release-notes-come-from-the-changelog.md)
  and its reference `templates/release-notes/release.yml`, whose two `awk`
  gates are reproduced here rather than adopted as a standalone workflow,
  since a release here never builds or signs inside the source repository's
  own CI). A profile without a maintained `CHANGELOG.md` simply cannot
  publish through this script — that's the intended failure mode, not a bug
  to work around with a fallback.
- **`macos-signing` has no required reviewer, by design.** See
  `SECURITY.md`'s "Required repository settings" item 4 for the reasoning
  (a sole maintainer approving their own request isn't real separation of
  duties) and what to reconsider if a second trusted maintainer joins. Don't
  "restore" it as an assumed-missing safety net without reading that
  section first — its absence is a recorded decision, not an oversight.
- **No `GitHubAttestationPolicy` in the apps this broker releases for.**
  Releases are built in *this* repository, not the source repository, so
  there is no GitHub attestation provenance from the source repo for
  AppUpdater to check against — requiring it would reject every genuine
  release. Relatedly, for a SwiftPM product, AppUpdater's `Bundle.module`
  resource lookup never looks in `Contents/Resources`, so attempting
  attestation verification there ends in a `fatalError` rather than a
  clean rejection (see `trsdn/OpenWritr#31`). The Developer ID, Team ID, and
  bundle ID checks still apply and are the real check.

## Review expectation for changes

- `main` requires a pull request with passing checks (`Tests and static
  validation`, `Unit tests on macOS`); there is no bypass for any actor,
  including administrators, per the ruleset — a direct push is rejected the
  same way for the owner as for anyone else.
- Add or update a test in `tests/test_broker.py` for any behavior change in
  `scripts/broker.py` — see `CONTRIBUTING.md`.
- Update `README.md` and `SECURITY.md` when behavior, setup, or the trust
  model changes. Letting code and these documents drift apart is exactly
  what happened with the `macos-signing` reviewer rule above — caught only
  because someone asked whether it was documented, not by any check.
- Fill in the PR template's security-impact section honestly; it exists so
  a reviewer doesn't have to reconstruct the blast radius from the diff
  alone.
