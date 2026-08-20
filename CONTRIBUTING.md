# Contributing

Thanks for your interest in the macOS notarization broker. This repository holds
privileged signing logic, so changes are reviewed against the security model in
[SECURITY.md](SECURITY.md) before anything else.

## Before you start

- Open an issue first for anything that changes the workflow, the broker
  scripts, or a profile. Small documentation fixes can go straight to a pull
  request.
- Do **not** report vulnerabilities in a public issue. Follow
  [SECURITY.md](SECURITY.md#reporting-a-vulnerability).
- Never attach Apple credentials, certificates, provisioning profiles, or
  private workflow logs to an issue or pull request.

## Local validation

Run the full check set from the repository root before pushing:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/validate-repository.py
python3 -m py_compile scripts/broker.py scripts/validate-repository.py
bash -n scripts/*.sh
ruby -e 'require "yaml"; YAML.load_file(".github/workflows/notarize.yml")'
```

`python3 -m unittest discover -s tests -v` is the primary test command; it needs
only a standard Python 3 installation with no third-party packages. CI runs the
same commands, so a clean local run should mean a green pull request.

## Pull requests

1. Branch from `main`.
2. Keep the change focused; unrelated cleanups belong in their own pull request.
3. Add or update tests in `tests/test_broker.py` for any behavior change in
   `scripts/broker.py`.
4. Update `README.md` and `SECURITY.md` when behavior, setup, or the trust model
   changes.
5. Fill in the pull request template, including the security impact section.
6. All CI checks must pass. `main` requires a pull request and passing checks.

Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`,
`chore:`, `refactor:`, `test:`), optionally scoped, for example
`fix(security): isolate notarization credentials`.

## Security constraints that must be preserved

A change is rejected if it weakens any of these, and
`scripts/validate-repository.py` enforces most of them mechanically:

- The dispatch gate keeps immutable numeric identity checks
  (`EXPECTED_BROKER_REPOSITORY_ID`, `AUTHORIZED_ACTOR_ID`) plus the
  `workflow_dispatch` event and `refs/heads/main` ref conditions. Do not replace
  numeric IDs with mutable login names.
- Application profiles stay declarative and allowlisted in
  `profiles/apps.json`; no shell fragments, hooks, secret names, or
  source-controlled entitlements.
- Apple secrets exist only in the `macos-signing` environment and are referenced
  only in the `sign` job. No other job or workflow may reference secrets or use
  an environment.
- Workflows declare `permissions: {}` at the top level and grant the minimum
  read-only scope per job.
- Untrusted source repository code never runs in the privileged job.
- Every `uses:` reference is pinned to a full 40-character commit SHA.
- GitHub expressions are never interpolated directly into `run:` shell bodies;
  pass them through `env:` instead.

## Dependency update process

This repository has no runtime package manifest. Its dependency surface is:

| Dependency | How it is pinned | How it is updated |
| --- | --- | --- |
| GitHub Actions (`uses:`) | Full commit SHA with a version comment | Weekly Dependabot pull request, reviewed and merged like any other change |
| GitHub-hosted runner images | `ubuntu-latest` / `macos-latest` | Tracked by GitHub; verified by CI runs |
| Broker-owned build locks (`profiles/locks/`) | Checked-in resolved lock files | Manual, reviewed pull request only |
| Source repository build dependencies | Pinned by the resolved release commit | Not updated here; a source release change requires a reviewed profile update |

Dependabot is configured in [`.github/dependabot.yml`](.github/dependabot.yml)
for the `github-actions` ecosystem. Dependabot security updates and vulnerability
alerts are enabled for the repository. Accept an action update only when the new
SHA belongs to the referenced tag in the upstream repository, and only for
GitHub-owned actions.

Never loosen a SHA pin to a tag or branch to make an update easier.

## Adding or changing an application profile

Profile changes alter what this broker will sign, so they get the strictest
review:

1. Update `profiles/apps.json` and any entitlements file under
   `profiles/entitlements/`.
2. Confirm the repository numeric ID is correct and immutable.
3. Add or update the corresponding assertions in `tests/test_broker.py`.
4. Explain in the pull request why the new bundle layout, entitlements,
   architecture, minimum macOS version, and dependency contract are acceptable.

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
