"""Canonical Agent Plugin projection into client-native MCP mappings."""

from __future__ import annotations

import json
from dataclasses import replace
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
from apm_cli.integration.mcp_integrator_native import prepare_agent_plugin_mcp_servers
from apm_cli.models.dependency.native_mcp import AgentPluginMCPPreparationFailure

pytestmark = pytest.mark.component


def _load_plugin(
    root: Path,
    servers: dict,
    *,
    name: str = "projection-test",
    version: str = "1.0.0",
    include_apm_components: bool = False,
) -> object:
    root.mkdir(parents=True)
    manifest = {
        "$schema": PLUGIN_SCHEMA_ID,
        "name": name,
        "version": version,
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
        for component_name in ("agents", "commands", "instructions", "extensions"):
            component = extension_root / component_name
            component.mkdir(parents=True)
            (component / f"{component_name}.txt").write_text(
                component_name,
                encoding="utf-8",
            )
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
    preparation = prepare_agent_plugin_mcp_servers(
        plugin,
        plugin_root=tmp_path / "installed",
        plugin_data=tmp_path / "data",
    )

    projection = project_agent_plugin_for_client(plugin, preparation, adapter)

    assert [skill.directory_name for skill in projection.skills] == ["demo"]
    assert {server.name for server in projection.mcp_servers} == {"local", "remote"}
    assert projection.mcp_servers[0].config
    assert projection.mcp_servers[0].preparation in preparation.successes
    assert projection.mcp_failures == ()
    assert len(projection.diagnostics) == 1
    diagnostic = projection.diagnostics[0]
    assert diagnostic.code is ClientProjectionDiagnosticCode.TRANSPORT_UNSUPPORTED
    assert diagnostic.capability is ClientProjectionCapability.MCP_SSE
    assert diagnostic.component == "mcp:sse"
    assert diagnostic.preparation is preparation.successes[2]
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
    preparation = prepare_agent_plugin_mcp_servers(
        plugin,
        plugin_root=tmp_path / "installed",
        plugin_data=tmp_path / "data",
    )

    def _must_not_render(_server_info):
        raise AssertionError("unsafe projection reached the renderer")

    monkeypatch.setattr(adapter, "render_server_config", _must_not_render)

    projection = project_agent_plugin_for_client(plugin, preparation, adapter)

    assert projection.mcp_servers == ()
    assert len(projection.diagnostics) == 1
    diagnostic = projection.diagnostics[0]
    assert diagnostic.code is ClientProjectionDiagnosticCode.RUNTIME_ENV_UNSUPPORTED
    assert diagnostic.capability is ClientProjectionCapability.MCP_STDIO
    assert diagnostic.component == "mcp:local"
    assert diagnostic.preparation is preparation.successes[0]


def test_projection_types_every_canonical_apm_component_omission(tmp_path: Path) -> None:
    plugin = _load_plugin(
        tmp_path / "plugin",
        {},
        include_apm_components=True,
    )
    adapter = CodexClientAdapter(project_root=tmp_path)
    preparation = prepare_agent_plugin_mcp_servers(
        plugin,
        plugin_root=tmp_path / "installed",
        plugin_data=tmp_path / "data",
    )

    projection = project_agent_plugin_for_client(plugin, preparation, adapter)

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
    assert all(diagnostic.preparation is None for diagnostic in projection.diagnostics)
    assert projection.is_complete is False


def test_projection_preserves_typed_mcp_preparation_failure(tmp_path: Path) -> None:
    plugin = _load_plugin(
        tmp_path / "plugin",
        {
            "local": {
                "type": "stdio",
                "command": "tool",
            }
        },
    )
    preparation = prepare_agent_plugin_mcp_servers(
        plugin,
        plugin_root=tmp_path / "installed",
        plugin_data=tmp_path / "data",
    )
    success = preparation.successes[0]
    failure = AgentPluginMCPPreparationFailure(
        server_name=success.server_name,
        provenance=success.provenance,
        code="target.prepare.failed",
        message="target adapter rejected the prepared server",
    )
    partial = replace(preparation, results=(failure,))

    projection = project_agent_plugin_for_client(
        plugin,
        partial,
        CodexClientAdapter(project_root=tmp_path),
    )

    assert projection.mcp_servers == ()
    assert projection.mcp_failures == (failure,)
    assert projection.diagnostics == ()
    assert projection.is_complete is False


def test_projection_rejects_incomplete_and_reordered_preparation_before_rendering(
    tmp_path: Path,
    monkeypatch,
) -> None:
    plugin = _load_plugin(
        tmp_path / "plugin",
        {
            "first": {"type": "stdio", "command": "first"},
            "second": {"type": "stdio", "command": "second"},
        },
    )
    preparation = prepare_agent_plugin_mcp_servers(
        plugin,
        plugin_root=tmp_path / "installed",
        plugin_data=tmp_path / "data",
    )
    adapter = CodexClientAdapter(project_root=tmp_path)
    monkeypatch.setattr(
        adapter,
        "render_server_config",
        lambda _server_info: pytest.fail("mismatched preparation reached the renderer"),
    )

    for results in (preparation.results[:1], tuple(reversed(preparation.results))):
        with pytest.raises(
            ValueError,
            match=r"^Client projection requires complete ordered MCP preparation results$",
        ):
            project_agent_plugin_for_client(
                plugin,
                replace(preparation, results=results),
                adapter,
            )


def test_projection_rejects_foreign_plugin_preparation_before_rendering(
    tmp_path: Path,
    monkeypatch,
) -> None:
    servers = {"local": {"type": "stdio", "command": "tool"}}
    plugin = _load_plugin(tmp_path / "plugin", servers)
    foreign_plugin = _load_plugin(
        tmp_path / "foreign",
        servers,
        name="foreign-plugin",
        version="2.0.0",
    )
    foreign_preparation = prepare_agent_plugin_mcp_servers(
        foreign_plugin,
        plugin_root=tmp_path / "foreign-installed",
        plugin_data=tmp_path / "foreign-data",
    )
    adapter = CodexClientAdapter(project_root=tmp_path)
    monkeypatch.setattr(
        adapter,
        "render_server_config",
        lambda _server_info: pytest.fail("foreign preparation reached the renderer"),
    )

    with pytest.raises(
        ValueError,
        match=r"^Client projection MCP preparation provenance does not match plugin IR$",
    ):
        project_agent_plugin_for_client(plugin, foreign_preparation, adapter)


def test_projection_rejects_server_declaration_mismatch_before_rendering(
    tmp_path: Path,
    monkeypatch,
) -> None:
    plugin = _load_plugin(
        tmp_path / "plugin",
        {
            "first": {"type": "stdio", "command": "first"},
            "second": {"type": "stdio", "command": "second"},
        },
    )
    preparation = prepare_agent_plugin_mcp_servers(
        plugin,
        plugin_root=tmp_path / "installed",
        plugin_data=tmp_path / "data",
    )
    first = preparation.successes[0]
    mismatched_provenance = replace(
        first.provenance,
        declaration=plugin.components.mcp_servers[1].provenance,
    )
    mismatched_first = replace(
        first,
        config=replace(first.config, provenance=mismatched_provenance),
    )
    mismatched_preparation = replace(
        preparation,
        results=(mismatched_first, *preparation.results[1:]),
    )
    adapter = CodexClientAdapter(project_root=tmp_path)
    monkeypatch.setattr(
        adapter,
        "render_server_config",
        lambda _server_info: pytest.fail("mismatched provenance reached the renderer"),
    )

    with pytest.raises(
        ValueError,
        match=r"^Client projection MCP result provenance does not match canonical server IR$",
    ):
        project_agent_plugin_for_client(plugin, mismatched_preparation, adapter)
