# APM, patched (`lk` builder branch)

This branch builds [microsoft/apm](https://github.com/microsoft/apm) with a small patch series and publishes
the wheel as a GitHub release (`v<upstream>+lk.<n>`). It holds no APM source: CI checks out the upstream tag
named in the `Makefile`, applies `patches/`, runs upstream's unit tests, builds the wheel and verifies it.

## Patches

| Patches | What they do |
|---|---|
| 0001–0007 | omp as an APM target: native MCP ownership, per-server targets, extensions and portable hooks; Codex entry fixes; `apm approve` grants; `apm outdated --json` |
| 0008–0013 | At user scope (`apm install -g`), MCP secrets stay environment references: Claude writes `${VAR}`, Codex `env_vars` / `env_http_headers` / `bearer_token_env_var`; nothing is looked up or prompted, and adapters that would resolve a reference refuse the server |

`tests/secret-references.sh` checks the second group against the built wheel: with fake values in the
environment, no value may land in `~/.claude.json` or `~/.codex/config.toml`. Upstream fails it.

## Releases

- A push to `lk` that changes the `Makefile` or `patches/` builds and, when every step passes, releases
  `v<APM_VERSION>+lk.<n>` with the wheel and `SHA256SUMS`. `n` restarts at 1 for each upstream version.
- Renovate bumps `APM_VERSION` when upstream releases. Patch releases merge on their own once CI is green;
  minor and major releases wait for review.
- Wheels are reproducible (`SOURCE_DATE_EPOCH`), so a rebuild of the same commit has the same sha256.

## When a patch no longer applies

The series is authored on `lk-patches/v<version>` (upstream tag + one commit per patch):

```sh
git fetch upstream --tags
git switch -c lk-patches/v0.36.0 lk-patches/v0.35.1
git rebase --onto v0.36.0 v0.35.1        # resolve conflicts, run the tests
git switch lk                            # on the Renovate PR branch
make refresh-patches APM_VERSION=0.36.0  # re-export patches/ from the new branch
```

Commit the refreshed `patches/` to the Renovate PR; CI builds it. Patches never touch the version,
`CHANGELOG.md` or `README.md`, so they don't conflict on every upstream release.

## Local build

Needs git, GNU make and [uv](https://docs.astral.sh/uv/):

```sh
make checkouts patches test
make wheel VERSION=$(make -s next-version)
make verify
```
