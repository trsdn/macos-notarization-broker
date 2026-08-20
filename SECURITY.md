# Security policy and deployment requirements

## Trust model

The four application repositories and everything they fetch during compilation
are untrusted. Their code may run only in the `build` job, which has:

- no Apple secrets;
- no Developer ID certificate;
- no protected environment;
- no write permissions; and
- an ephemeral runner that is discarded before preflight and signing.

The unsigned artifact is also untrusted. A fresh secretless job validates and
sanitizes it. The privileged job checks out only the broker repository at the
workflow commit, downloads the exact immutable artifact ID produced by
preflight, repeats validation before certificate import, and uses only
`scripts/broker.py` for privileged operations.

The broker validates identity and structure, not application behavior. An
authorized release request can still sign malicious application logic if it is
present in the resolved commit or its pinned build dependencies.

The repository also runs a continuous integration workflow
(`.github/workflows/ci.yml`) on pull requests and pushes to `main`. It is
deliberately outside the signing trust boundary: it has no Apple secrets, no
protected environment, and read-only permissions, and it only runs the tests and
static checks in this repository. `scripts/validate-repository.py` fails if any
workflow other than `notarize.yml` references a secret, uses an environment,
grants a non-read permission, uses `pull_request_target`, uses an unpinned
action, or interpolates a GitHub expression into a shell command.

## Required repository settings

The checked-in workflow is only one part of the control plane. These settings
are configured on the repository and must stay in place:

1. Keep `main` as the default branch.
2. Protect `main` with a ruleset that:
   - requires pull requests for changes;
   - requires the `Tests and static validation` and `Unit tests on macOS` status
     checks to pass on the merge candidate;
   - dismisses stale approvals on new pushes and requires review threads to be
     resolved;
   - blocks force pushes and branch deletion; and
   - grants no bypass permission to any actor or role, including repository
     administrators.

   The rules apply to the repository owner as well: a direct push to `main` is
   rejected, and every change must land through a pull request whose checks
   passed. Relaxing a rule therefore requires an auditable change to the ruleset
   itself, not a silent bypass on a single merge.

   `.github/CODEOWNERS` assigns `.github/workflows/**`, `scripts/**`, and
   `profiles/**` to the repository owner. While a single maintainer owns the
   repository, code owner approval cannot be a hard ruleset requirement without
   forcing a bypass on every merge, which would also bypass the required status
   checks. Enable `require_code_owner_review` as soon as a second trusted
   maintainer exists.
3. Keep the five Apple values only in the `macos-signing` environment.
4. Restrict `macos-signing` to the `main` branch and configure a required
   reviewer. If a sole maintainer must self-approve, keep
   `prevent_self_review` disabled and understand that approval is an
   operational confirmation rather than separation of duties.
5. Remove old repository-level Apple secrets.
6. Allow only GitHub-owned actions. The workflow additionally pins every
   action to a full commit SHA.
7. Keep Dependabot alerts, Dependabot security updates, secret scanning, and
   secret scanning push protection enabled.
8. Grant write/admin access only to trusted maintainers. The workflow itself
   accepts dispatch only when all of these are true:
   - event is `workflow_dispatch`;
   - repository is `trsdn/macos-notarization-broker`;
   - repository numeric ID is `1315404585`;
   - ref is `refs/heads/main`; and
   - actor numeric ID is `24534196`.

If ownership changes, update the repository and actor numeric IDs in a reviewed
change. Do not replace them with mutable login-name-only checks.

### Safe publication sequence

Some GitHub plans do not provide required reviewers or branch rules while a
repository is private. In that case:

1. Keep a local backup of the Apple credentials.
2. Delete all five repository-level secrets before changing visibility.
3. Make the repository public with Actions disabled, or do not dispatch it.
4. Configure the `macos-signing` environment, its `main` branch policy, a
   required reviewer, and the `main` ruleset.
5. Run `scripts/setup-secrets.sh` to store environment-scoped secrets.
6. Verify that `gh secret list --repo trsdn/macos-notarization-broker` does not
   list any of the five Apple secret names before enabling dispatch.

This repository does not automate or change repository visibility.

## Fork and outside-user behavior

The notarization workflow has no `pull_request`, `pull_request_target`, `push`,
or scheduled triggers. GitHub requires write access to dispatch an upstream
manual workflow, and the workflow has an additional fixed actor gate.

A public fork can modify and run its own copy of the workflow, but a fork does
not receive the upstream `macos-signing` environment or its secrets. Its
repository numeric ID also fails the upstream identity gate.

A pull request from a fork does run the CI workflow. That workflow is secretless
and read-only, uses `pull_request` rather than `pull_request_target`, and
therefore executes untrusted contributor code only in a disposable, unprivileged
runner with no access to repository secrets or the `GITHUB_TOKEN` write scopes.

## Tag and artifact integrity

- Tags are dereferenced to a full commit SHA before the build starts.
- Annotated tags are recursively resolved with a bounded depth.
- The external checkout fetches the recorded SHA, never the tag.
- The tag is resolved again immediately before privileged work and the run
  fails if it moved.
- Artifact handoff addresses artifacts by their immutable numeric artifact ID
  (`artifact-ids`), never by name, so a later upload cannot shadow the bytes a
  downstream job consumes.
- Preflight records archive, tree, executable, nested executable, source, and
  profile digests.
- The privileged job repeats archive and tree validation before importing the
  certificate, and re-verifies every digest the preflight manifest recorded.
- Final provenance records the source commit and release-file SHA-256 values.

## Profile review requirements

Profiles may contain only declarative repository, bundle, validation, signing,
and output policy. Do not add:

- shell fragments;
- arbitrary hooks;
- source-controlled entitlement files;
- secret names;
- credentials of any kind; or
- nested executable code that is not named exactly, path by path.

The Apple Team ID is deliberately not in that list. See
[Apple Team ID as declarative policy](#apple-team-id-as-declarative-policy).

All profiles reject symlinks, executable resources, provisioning profiles, and
pre-existing identity-backed signatures. Nested bundles — `.app`, `.appex`,
`.bundle`, `.framework`, `.xpc` — are rejected for every profile. Undeclared
nested Mach-O code and undeclared executable files are rejected for every
profile.

## Nested executable code

A profile may ship a second executable, such as a privileged launch daemon
helper, only when a reviewed profile names it exactly. There are no globs, no
directories, and no "allow anything under this path" escape. The invariant is
unchanged: the privileged job only ever signs bytes that a secretless job
already described.

Each entry in `nested_executables` declares:

- `path` — an exact bundle-relative path under `Contents/`;
- `identifier` — the code signing identifier for that executable;
- `entitlements` — a broker-owned entitlements plist;
- `embedded_info_plist` — optional exact expectations checked against the
  `__TEXT,__info_plist` section of the built binary; and
- `launch_daemon` — the optional bundled job to pin.

The secretless preflight then:

- validates every declared executable exactly as it validates the main one:
  regular file, not a symlink, Mach-O, expected architectures;
- records a SHA-256 for each entry in the preflight manifest;
- still fails on any Mach-O or executable file that is not declared;
- pins a declared launch daemon by `Label` and `BundleProgram`, requires the
  program to be the declared nested executable, and rejects `Program` and
  `ProgramArguments` because both can point outside the bundle; and
- allowlists the launchd job directories by exact path. A job plist is neither
  Mach-O nor executable, so the checks above cannot see it. Any file or
  directory under `Contents/Library/LaunchDaemons` or
  `Contents/Library/LaunchAgents` that is not the declared `launch_daemon`
  path is rejected. Without this, a bundle could ship a second, unreviewed job
  definition next to the pinned one and register it at runtime, and every
  digest would still agree because the file was described but never policed.

Directory matching is case-insensitive because macOS filesystems are, so
`Contents/Library/launchdaemons` names the same directory on the user's machine
and cannot be used to slip past the allowlist. The comparison uses `casefold()`
rather than `lower()` because APFS applies full Unicode case folding: `lower()`
leaves `U+017F LATIN SMALL LETTER LONG S` unchanged, so `LaunchAgentſ` would
evade a `lower()`-based test while still resolving to `LaunchAgents` at runtime.
The comparison against a declared path stays exactly case-sensitive, so a bundle
whose spelling differs from its profile is rejected rather than silently
accepted. The same folding applies to the nested-bundle suffix check.

The privileged job re-verifies every recorded digest before importing the
certificate, signs inside-out — each nested executable first, then the enclosing
app — verifies each signature against its declared identifier and entitlements,
and re-verifies the whole payload after stapling and inside every repackaged
artifact.

## Apple Team ID as declarative policy

A helper that embeds a client code requirement needs the Team ID while it
compiles, which is before any secret exists in the pipeline. The broker resolves
this without moving a secret across the boundary: `team_id` is a declarative
profile field that the build adapter passes to `xcodebuild` as
`DEVELOPMENT_TEAM`.

A Team ID is not a credential. It is printed by `codesign -dv` on any signed
artifact and is embedded in every notarized binary. The certificate, Apple ID,
and app-specific password stay in the `macos-signing` environment and remain
unreachable from the build and preflight jobs;
`scripts/validate-repository.py` fails if either job references
`APPLE_TEAM_ID`.

Two checks keep the declared value honest:

- the privileged job refuses to sign when `team_id` does not equal
  `APPLE_TEAM_ID`; and
- when a profile declares an `embedded_info_plist` expectation containing a
  `{team_id}` placeholder, the secretless preflight also compares the declared
  Team ID against the value the build actually embedded in that nested binary,
  so a helper compiled with an empty or wrong team cannot reach the signing job.

The second check is opt-in policy: `embedded_info_plist` is an optional field,
so a profile that omits it gets no embedded-team comparison. A profile that
ships a nested executable embedding a client code requirement must declare the
expectation, otherwise only the first check applies.

## Residual risks

- GitHub-hosted runner images and Apple/GitHub services remain trusted
  dependencies.
- Compiler or parser vulnerabilities could affect a secretless preflight or
  privileged signing runner. Sanitization and fresh-runner boundaries reduce
  but do not eliminate this risk.
- md2loop uses a broker-owned `Package.resolved` because its tagged source did
  not contain one. Future dependency changes require a reviewed lock update.
- OpenWritr uses its source-committed dependency lock. Teleprompter Mirror and
  Ptions+ currently have no external package resolution in their release
  builds.
- Structural validation does not prove that application behavior is benign. A
  declared nested executable is validated and pinned, not vetted; a privileged
  helper still runs source-repository logic with the privileges its bundled
  launch daemon requests.
- Apple credentials must still be rotated if the environment, certificate, or
  maintainer account is compromised.

## Dependency updates

Actions are pinned to full commit SHAs and updated weekly through Dependabot
(`.github/dependabot.yml`), reviewed like any other change. Broker-owned build
locks under `profiles/locks/` change only through a manual, reviewed pull
request. Dependabot alerts and Dependabot security updates are enabled. The full
process, including what must never be loosened, is documented in
[CONTRIBUTING.md](CONTRIBUTING.md#dependency-update-process).

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories:
[Report a vulnerability](https://github.com/trsdn/macos-notarization-broker/security/advisories/new).

Do not open a public issue, and do not include Apple credentials, certificates,
or private workflow logs in any report. Expect an initial response within seven
days. Please allow a fix to ship before public disclosure.
