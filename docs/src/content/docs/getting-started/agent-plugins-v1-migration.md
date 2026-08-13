---
title: Agent Plugins v1 migration
description: Repack Claude or legacy APM bundles to the Agent Plugins v1 default, or keep the old layout only when you need it.
sidebar:
  order: 5
---

APM now defaults to Agent Plugins v1 for `apm pack` and `apm plugin init`.
Use the historical layouts only when a downstream consumer still requires them.

## Pick the output

| Situation | Command | Result |
|---|---|---|
| New authoring or CI | `apm pack` / `apm plugin init` | Agent Plugins v1 default |
| Claude host still needs the old layout | `apm pack --claude-plugin` / `apm plugin init --claude-plugin` | Historical Claude layout |
| Legacy APM bundle pipeline | `apm pack --format apm` | Legacy bundle for `apm unpack` only |

## Repack, then install

```bash
apm pack
apm install ./build/<name>
```

If you publish archives instead of directories:

```bash
apm pack --archive
apm install ./build/<name>.zip
```

## CI check

```yaml
- run: apm install
- run: apm pack --check-versions --check-clean
- run: apm audit --ci
```

## Warning schedule

| Release | Behavior |
|---|---|
| 0.29.0-0.33.x | Successful legacy-compatible builds print the migration warning. |
| 0.34.0 | The warning is removed. |

## Compatibility FAQ

### Agent

Use the default. `plugin.json` at the bundle root is the canonical Agent Plugins v1 output.

### Claude

Use `--claude-plugin` only when the consumer still expects the historical Claude layout. If the consumer accepts `plugin.json`, stay on the default.

### APM

Use `--format apm` only for legacy bundle consumers. `apm install` rejects those bundles; use `apm unpack` only for that path.

## Related

- [Pack a bundle](../../producer/pack-a-bundle/)
- [Deploy a local bundle](../../consumer/deploy-a-bundle/)
- [apm pack](../../reference/cli/pack/)
- [apm plugin init](../../reference/cli/plugin/)
- [apm unpack](../../reference/cli/unpack/)
- [Security model](../../enterprise/security/)
