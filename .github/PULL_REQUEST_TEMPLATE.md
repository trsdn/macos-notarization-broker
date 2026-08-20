# Summary

<!-- What changes and why. Link the issue, for example "Closes #12". -->

## Type of change

- [ ] Documentation only
- [ ] Broker logic (`scripts/`)
- [ ] Workflow (`.github/workflows/`)
- [ ] Application profile (`profiles/`)
- [ ] Tests or CI
- [ ] Repository configuration

## Validation

<!-- Paste or summarize results. CI runs the same commands. -->

- [ ] `python3 -m unittest discover -s tests -v`
- [ ] `python3 scripts/validate-repository.py`
- [ ] `python3 -m py_compile scripts/broker.py scripts/validate-repository.py`
- [ ] `bash -n scripts/*.sh`
- [ ] `ruby -e 'require "yaml"; YAML.load_file(".github/workflows/notarize.yml")'`

## Security impact

<!-- Required. Write "None" only if nothing below is affected. -->

- [ ] Immutable numeric actor and repository ID validation is unchanged or
      strengthened.
- [ ] Profile allowlist enforcement is unchanged or strengthened.
- [ ] Apple secrets remain scoped to the `macos-signing` environment and are
      referenced only in the `sign` job.
- [ ] Workflow permissions remain read-only and least-privilege.
- [ ] Untrusted source repository code still never runs in the privileged job.
- [ ] Every `uses:` reference is still pinned to a full commit SHA.
- [ ] No credentials, certificates, or private logs are included in this pull
      request.

## Documentation

- [ ] `README.md` updated, or not affected.
- [ ] `SECURITY.md` updated, or not affected.
- [ ] `CONTRIBUTING.md` updated, or not affected.
