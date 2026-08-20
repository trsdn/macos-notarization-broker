# macOS notarization broker

Private GitHub Actions broker that stores Apple credentials once and creates
notarized artifacts for four fixed repositories:

- `trsdn/md2loop`
- `trsdn/OpenWritr`
- `trsdn/PtionsPlus`
- `trsdn/teleprompter-mirror-macos`

## Setup

Configure the five repository secrets from a local Developer ID P12:

```bash
scripts/setup-secrets.sh /path/to/developer-id.p12
```

## Run

Run locally with the installed Developer ID certificate and the existing
`OpenWritr` notarytool keychain profile:

```bash
scripts/local.sh md2loop v1.0.2
```

To use GitHub Actions, choose **Actions → Notarize macOS release → Run
workflow**, or dispatch and download the result:

```bash
scripts/request.sh md2loop v1.0.2
```

The workflow accepts only a fixed application profile and an exact version
tag. It checks out that tag, runs the repository's existing release scripts,
and uploads the notarized files as a private workflow artifact.
