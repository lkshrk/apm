"""Canonical Agent Plugin projection into client-native MCP mappings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from apm_cli.adapters.client.agent_plugin_projection import (
    ClientProjectionCapability,
    ClientProjectionDiagnosticCode,
    project_agent_plugin_for_client,
)
from apm_cli.adapters.client.codex import CodexClientAdapter
from apm_cli.agent_plugins import (
    COM_MICROSOFT_APM_NAMESPACE,
    COM_MICROSOFT_APM_SCHEMA_VERSION,
    MCP_SCHEMA_ID,
    PLUGIN_SCHEMA_ID,
    load_agent_plugin,
)

pytestmark = pytest.mark.component


def _load_plugin(root: Path, servers: dict, *, include_apm_components: bool = False) -> object:
    root.mkdir(parents=True)
    manifest = {
        "$schema": PLUGIN_SCHEMA_ID,
        "name": "projection-test",
        "version": "1.0.0",
        "description": "Projection fixture",
    }
    if include_apm_components:
        manifest["extensions"] = {
            COM_MICROSOFT_APM_NAMESPACE: {"schemaVersion": COM_MICROSOFT_APM_SCHEMA_VERSION}
        }
    (root / "plugin.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    (root / "mcp.json").write_text(
        json.dumps({"$schema": MCP_SCHEMA_ID, "mcpServers": servers}),
        encoding="utf-8",
    )
    skill = root / "skills" / "demo"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: demo\ndescription: Demo projection skill\n---\n\nUse this skill.\n",
        encoding="utf-8",
    )
    if include_apm_components:
        extension_root = root / COM_MICROSOFT_APM_NAMESPACE
        for name in ("agents", "commands", "instructions", "extensions"):
            component = extension_root / name
            component.mkdir(parents=True)
            (component / f"{name}.txt").write_text(name, encoding="utf-8")
        (extension_root / "lsp.json").write_text(
            json.dumps(
                {
                    "lspServers": {
                        "python": {
                            "command": "pyright-langserver",
                            "extensionToLanguage": {".py": "python"},
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        hooks = extension_root / "hooks"
        hooks.mkdir()
        (hooks / "hooks.json").write_text(
            json.dumps({"preCommit": [{"command": "lint"}]}),
            encoding="utf-8",
        )
    return load_agent_plugin(root)


def test_projection_renders_supported_facts_and_accounts_for_unsupported(
    tmp_path: Path,
) -> None:
    plugin = _load_plugin(
        tmp_path / "plugin",
        {
            "local": {
                "type": "stdio",
                "command": "tool",
                "args": ["--serve"],
            },
            "remote": {
                "type": "streamable-http",
                "url": "https://example.com/mcp",
            },
            "sse": {
                "type": "sse",
                "url": "https://example.com/events",
            },
        },
    )
    adapter = CodexClientAdapter(project_root=tmp_path)

    projection = project_agent_plugin_for_client(plugin, adapter)

    assert [skill.directory_name for skill in projection.skills] == ["demo"]
    assert {server.name for server in projection.mcp_servers} == {"local", "remote"}
    assert projection.mcp_servers[0].config
    assert len(projection.diagnostics) == 1
    diagnostic = projection.diagnostics[0]
    assert diagnostic.code is ClientProjectionDiagnosticCode.TRANSPORT_UNSUPPORTED
    assert diagnostic.capability is ClientProjectionCapability.MCP_SSE
    assert diagnostic.component == "mcp:sse"
    assert len(projection.mcp_servers) + len(projection.diagnostics) == len(
        plugin.components.mcp_servers
    )
    assert projection.is_complete is False


def test_projection_returns_typed_runtime_env_diagnostic_without_rendering(
    tmp_path: Path,
    monkeypatch,
) -> None:
    plugin = _load_plugin(
        tmp_path / "plugin",
        {
            "local": {
                "type": "stdio",
                "command": "tool",
                "env": {"TOKEN": "${TOKEN}"},
            }
        },
    )
    adapter = CodexClientAdapter(project_root=tmp_path)

    def _must_not_render(_server_info):
        raise AssertionError("unsafe projection reached the renderer")

    monkeypatch.setattr(adapter, "render_server_config", _must_not_render)

    projection = project_agent_plugin_for_client(plugin, adapter)

    assert projection.mcp_servers == ()
    assert len(projection.diagnostics) == 1
    diagnostic = projection.diagnostics[0]
    assert diagnostic.code is ClientProjectionDiagnosticCode.RUNTIME_ENV_UNSUPPORTED
    assert diagnostic.capability is ClientProjectionCapability.MCP_STDIO
    assert diagnostic.component == "mcp:local"


def test_projection_types_every_canonical_apm_component_omission(tmp_path: Path) -> None:
    plugin = _load_plugin(
        tmp_path / "plugin",
        {},
        include_apm_components=True,
    )
    adapter = CodexClientAdapter(project_root=tmp_path)

    projection = project_agent_plugin_for_client(plugin, adapter)

    assert projection.skills
    assert projection.mcp_servers == ()
    assert {
        diagnostic.component: diagnostic.capability for diagnostic in projection.diagnostics
    } == {
        "apm:agents": ClientProjectionCapability.APM_AGENTS,
        "apm:commands": ClientProjectionCapability.APM_COMMANDS,
        "apm:instructions": ClientProjectionCapability.APM_INSTRUCTIONS,
        "apm:extensions": ClientProjectionCapability.APM_EXTENSIONS,
        "apm:hooks": ClientProjectionCapability.APM_HOOKS,
        "apm:lsp": ClientProjectionCapability.APM_LSP,
    }
    assert all(
        diagnostic.code is ClientProjectionDiagnosticCode.COMPONENT_UNSUPPORTED
        for diagnostic in projection.diagnostics
    )
    assert projection.is_complete is False
