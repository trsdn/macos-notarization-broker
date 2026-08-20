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
- Artifact handoff uses immutable v4 artifact IDs.
- Preflight records archive, tree, executable, source, and profile digests.
- The privileged job repeats archive and tree validation before importing the
  certificate.
- Final provenance records the source commit and release-file SHA-256 values.

## Profile review requirements

Profiles may contain only declarative repository, bundle, validation, signing,
and output policy. Do not add:

- shell fragments;
- arbitrary hooks;
- source-controlled entitlement files;
- secret names;
- build-time credentials; or
- exceptions that permit nested executable code without an inside-out signing
  and validation design.

The current profiles intentionally reject nested apps, frameworks, plug-ins,
XPC services, dylibs, symlinks, executable resources, provisioning profiles,
and pre-existing identity-backed signatures.

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
- Structural validation does not prove that application behavior is benign.
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
