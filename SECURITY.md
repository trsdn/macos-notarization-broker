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

## Required repository settings before public release

The checked-in workflow is only one part of the control plane. Configure these
settings before changing repository visibility:

1. Keep `main` as the default branch.
2. Protect `main` with a ruleset that:
   - requires pull requests for changes;
   - requires review by a trusted owner for `.github/workflows/**`,
     `scripts/**`, and `profiles/**`;
   - blocks force pushes and branch deletion; and
   - limits bypass permission to the minimum number of trusted administrators.
3. Keep the five Apple values only in the `macos-signing` environment.
4. Restrict `macos-signing` to the `main` branch and configure a required
   reviewer. If a sole maintainer must self-approve, keep
   `prevent_self_review` disabled and understand that approval is an
   operational confirmation rather than separation of duties.
5. Remove old repository-level Apple secrets.
6. Allow only GitHub-owned actions. The workflow additionally pins every
   action to a full commit SHA.
7. Grant write/admin access only to trusted maintainers. The workflow itself
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

There are no `pull_request`, `pull_request_target`, `push`, or scheduled
triggers. GitHub requires write access to dispatch an upstream manual workflow,
and the workflow has an additional fixed actor gate.

A public fork can modify and run its own copy of the workflow, but a fork does
not receive the upstream `macos-signing` environment or its secrets. Its
repository numeric ID also fails the upstream identity gate.

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

## Reporting a vulnerability

Do not include Apple credentials, certificates, or private workflow logs in a
public issue. Use the repository owner's private security-reporting channel.
