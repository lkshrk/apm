---
title: apm import
description: Adopt existing Claude and Codex user state into APM.
sidebar:
  order: 4
---

## Synopsis

```bash
apm import --global --from claude --from codex \
  [--candidate-file <absolute-path>] [--plan-json <absolute-path>] \
  [--coordinator standalone|omni-v24] --format json

apm import --global --candidate-file <absolute-path> \
  --apply-plan <absolute-path> [--coordinator standalone|omni-v24] \
  [--omni-preimage-set <hash> --token-stdin] --format json
```

Planning inventories supported user-global Claude and Codex primitives without
creating APM state. Candidate and plan files are deterministic, strict-schema
JSON and must be absolute owner-only files in one secured operation directory.
Literal MCP secrets are replaced with a blocking sentinel and never printed.

Machine output is a strict typed envelope. Scan returns
`{"ok":true,"kind":"import-plan","plan":{...}}`. Mutating and recovery
commands return `{"ok":true,"kind":"import-*-result","result":{...}}`.
Failures return only
`{"ok":false,"kind":"import-error","error":{"code":"...","message":"..."}}`;
an operation ID is included when one is known.

Applying a reviewed plan snapshots local-only resources, registers
marketplaces, adopts packages into the global manifest, runs the normal APM
install service, verifies ownership, and journals every phase. Marketplace
plugins use marketplace dependencies rather than mutable native cache paths.

## Recovery

```bash
apm import status --operation <id> --format json
apm import resume --operation <id> --candidate-file <absolute-path> \
  --apply-plan <absolute-path> --coordinator <mode> --format json
apm import rollback --operation <id> --format json
apm import cleanup --operation <id> --confirm --format json
```

`rollback` is limited to phases before native integration becomes
resume-only. `cleanup` is idempotent and only accepts completed or rolled-back
operations.

The `omni-v24` coordinator supplies a 256-bit capability through stdin. APM
stores only its hash and returns `awaiting-external-commit`; after Omni commits
its config, finalize the matching operation:

```bash
apm import finalize --operation <id> --omni-preimage-set <hash> \
  --token-stdin --format json
```

All other APM lifecycle mutations remain fenced until finalize completes.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Plan, complete apply, external-commit fence, status, or recovery succeeded. |
| `2` | CLI usage is invalid. |
| `5` | Candidate, plan, coordinator, capability, or source protocol is incompatible. |
| `6` | Apply stopped in a journaled recoverable partial state. |
