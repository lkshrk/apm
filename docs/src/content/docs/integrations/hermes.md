---
title: "Hermes Agent"
description: "Deploy APM skills, AGENTS.md instructions, and MCP servers to the Hermes autonomous agent."
sidebar:
  order: 8
---

Hermes is a stable target included in `--target all`. Select it with
`--target hermes`, list it in `apm.yml`, or create a project-local `.hermes/`
directory for APM to detect it. `apm targets` shows this activation signal.

The project-local `.hermes/` directory is an APM marker, not a native Hermes
skill directory. The shared `.agents/` directory alone does not activate Hermes.

## What it does

[Hermes](https://hermes-agent.nousresearch.com) (by Nous Research) is a terminal-native autonomous agent that lives in a home directory (`~/.hermes/`) and talks to users over messaging platforms such as Telegram and Discord. Hermes natively reads two open standards that APM already emits:

- the [agentskills.io](https://agentskills.io) `SKILL.md` format for skills, and
- the `AGENTS.md` context-file standard for instructions.

So the `hermes` target reuses APM's existing skill and `AGENTS.md` output paths and adds one Hermes-specific writer for MCP servers (Hermes uses a YAML `mcp_servers:` block, distinct from the JSON `mcpServers` schema of other clients).

| APM primitive | Hermes surface | Location |
|---------------|----------------|----------|
| skills | Skills system (agentskills.io) | `.agents/skills/<name>/SKILL.md` (project) or `~/.hermes/skills/<name>/SKILL.md` (`--global`) |
| instructions | Context file (`AGENTS.md`) | `AGENTS.md` at the project root |
| MCP servers | `mcp_servers:` block | `~/.hermes/config.yaml` (home-scoped when Hermes is selected) |

At project scope, skills land in `.agents/skills/`. Add that directory's absolute
path to Hermes' [`skills.external_dirs` setting](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills/#external-skill-directories)
to make them discoverable. At user scope (`--global`), skills land directly in
the Hermes home.

## Install

```bash
# Project scope: skills -> .agents/skills/, MCP -> ~/.hermes/config.yaml
apm install --target hermes

# User scope: skills -> ~/.hermes/skills/, MCP -> ~/.hermes/config.yaml
apm install --target hermes --global
```

Compile instructions into one top-level `AGENTS.md`, since Hermes does not
read nested `AGENTS.md` files:

```bash
apm compile --target hermes --single-agents
```

APM uses `AGENTS.md` for package instructions and leaves `SOUL.md` unchanged.

## HERMES_HOME override

By default the user-scope root is `~/.hermes`. Set `HERMES_HOME` to point APM at a different Hermes home (useful for containers and multi-profile setups):

```bash
export HERMES_HOME="$HOME/.config/hermes"
apm install --target hermes --global
```

When `HERMES_HOME` lives under `$HOME`, APM keeps the deploy root home-relative; otherwise it uses the absolute path. The directory does not need to exist yet.

## MCP servers

When `hermes` is selected as an install target, APM writes MCP servers into the
home-scoped `mcp_servers:` block of `$HERMES_HOME/config.yaml` (default
`~/.hermes/config.yaml`), even when package skills use project scope:

Explicit selection does not require an existing Hermes home or a `hermes`
binary on `PATH`; APM creates the configured home as needed. Runtime-presence
signals are only relevant to automatic runtime discovery, which does not
select Hermes. APM's project target detection uses the `.hermes/` marker instead.

```yaml
mcp_servers:
  my-server:
    command: npx
    args: ["-y", "my-mcp-package"]
    env:
      MY_TOKEN: "..."
    enabled: true
```

HTTP servers are written with `url` and optional `headers` instead of `command`/`args`. APM merges into the existing `mcp_servers:` block and preserves every other top-level key in `config.yaml` (model provider, platform settings, and so on). All writes go through APM's YAML helper, so existing comments outside the managed block are the only thing not preserved by a safe-dump rewrite.

## Skills and instructions

- Skills deploy as `SKILL.md` content, unchanged from the agentskills.io format APM already produces.
- Instructions compile to `AGENTS.md`, which Hermes reads as a first-class context file.
- Agents, prompts, hooks, and commands are not part of the Hermes surface and are skipped for this target.

## Troubleshooting

- MCP servers not written: pass `--target hermes`; Hermes is never selected by automatic runtime discovery.
- Skills not picked up at project scope: ensure Hermes' `skills.external_dirs` includes `.agents/skills/`.
- Wrong home directory: set `HERMES_HOME` to the Hermes home you want to target.

See also [IDE and Tool Integration](../ide-tool-integration/).
