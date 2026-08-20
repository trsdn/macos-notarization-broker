# macOS notarization broker

A manual GitHub Actions broker for producing notarized artifacts for four fixed
public repositories:

- `trsdn/md2loop`
- `trsdn/OpenWritr`
- `trsdn/PtionsPlus`
- `trsdn/teleprompter-mirror-macos`

The repository can be made public without exposing Apple credentials to source
repository code. Repository visibility is not managed by this project.

## Security design

The workflow has four isolated jobs:

1. **Resolve** authorizes the fixed repository, repository ID, owner actor ID,
   `main` branch, and manual event. It dereferences the requested tag through
   the GitHub API to a full commit SHA.
2. **Build** checks out only that commit and builds an unsigned or linker-signed
   app. This job has no signing environment, Apple secrets, or certificate.
3. **Preflight** runs on a fresh secretless runner. It rejects unsafe ZIP paths,
   symlinks, special files, nested code, unexpected executables, wrong bundle
   identity/version/architecture, identity-backed signatures, and oversized
   artifacts. It then repackages a sanitized bundle.
4. **Sign** runs on another fresh runner using the protected
   `macos-signing` environment. Before referencing any Apple secret, it
   revalidates the sanitized bundle and confirms that the tag still resolves
   to the recorded commit. Only broker-owned Python code imports the
   certificate, signs, notarizes, staples, verifies, packages, and calculates
   checksums.

External source scripts are never executed in the privileged job. All action
dependencies are pinned to full action commit SHAs, and workflow permissions
are empty by default and read-only per job.

See [SECURITY.md](SECURITY.md) before making the repository public.

## Setup

Configure the five Apple values as **environment secrets**, not repository
secrets:

```bash
APPLE_TEAM_ID=YOURTEAMID scripts/setup-secrets.sh /path/to/developer-id.p12
```

The script creates or verifies the `macos-signing` environment and restricts it
to `main`. On the first run it may stop after creating the environment so that
you can add a required reviewer in repository settings. Rerun it to store:

- `MACOS_CERTIFICATE`
- `MACOS_CERTIFICATE_PWD`
- `APPLE_ID`
- `APPLE_TEAM_ID`
- `APPLE_APP_PASSWORD`

After all environment secrets are stored, the script removes repository-level
copies of the same names. Configure the repository rules described in
[SECURITY.md](SECURITY.md).

## Run

Use **Actions → Notarize macOS release → Run workflow** from `main`, or:

```bash
scripts/request.sh md2loop v1.0.2
```

`request.sh` supplies a unique request ID, correlates the exact workflow run,
downloads only its named artifact, and verifies `provenance.json` plus release
digests.

Direct local signing has intentionally been disabled. `scripts/local.sh` now
dispatches the hardened workflow because local source execution could otherwise
read an installed Developer ID identity or notarytool credential.

## Profiles and outputs

Profile policy is declarative in `profiles/apps.json`; entitlements and the
md2loop dependency lock are broker-owned files under `profiles/`.

Existing output names remain available:

- md2loop: `md2loop-VERSION-macos.dmg`
- OpenWritr: arm64 ZIP and DMG
- Ptions+: `Ptions+.zip` and `Ptions+.dmg`
- Teleprompter Mirror: arm64 ZIP

Every distributable now also receives a `.sha256` file. The workflow artifact
also contains `provenance.json` and `preflight-manifest.json`.

Profile validation is deliberately strict. A source release that changes its
bundle identifier, executable, app layout, architecture, entitlement policy,
minimum macOS version, or dependency contract requires a reviewed broker
profile update.

## Validate changes

```bash
python3 -m unittest discover -s tests -v
python3 scripts/validate-repository.py
python3 -m py_compile scripts/broker.py scripts/validate-repository.py
bash -n scripts/*.sh
ruby -e 'require "yaml"; YAML.load_file(".github/workflows/notarize.yml")'
```
