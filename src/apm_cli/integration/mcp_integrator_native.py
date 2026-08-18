"""Pure native Agent Plugin MCP preparation from canonical IR."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apm_cli.agent_plugins.ir import AgentPlugin, AgentPluginMcpServer
    from apm_cli.models.dependency.native_mcp import (
        AgentPluginMCPPreparation,
        AgentPluginMCPPreparationSuccess,
        AgentPluginMCPProvenance,
    )

_AGENT_PLUGIN_MCP_PLACEHOLDER = re.compile(r"\$\{(?P<name>PLUGIN_ROOT|PLUGIN_DATA)\}")


def _expand_agent_plugin_mcp_value(
    value: str,
    *,
    plugin_root: str,
    plugin_data: str,
) -> str:
    """Expand only portable Agent Plugin path placeholders in one literal."""
    replacements = {
        "PLUGIN_ROOT": plugin_root,
        "PLUGIN_DATA": plugin_data,
    }
    return _AGENT_PLUGIN_MCP_PLACEHOLDER.sub(
        lambda match: replacements[match.group("name")],
        value,
    )


def _prepare_agent_plugin_mcp_server(
    server: AgentPluginMcpServer,
    provenance: AgentPluginMCPProvenance,
    *,
    plugin_root: str,
    plugin_data: str,
) -> AgentPluginMCPPreparationSuccess:
    """Project one validated IR server without legacy normalization or auth."""
    from apm_cli.models.dependency.native_mcp import (
        AgentPluginMCPPreparationSuccess,
        AgentPluginMCPServerConfig,
        AgentPluginMCPServerProvenance,
    )

    server_provenance = AgentPluginMCPServerProvenance(
        plugin=provenance,
        declaration=server.provenance,
    )
    config = AgentPluginMCPServerConfig(
        name=server.name,
        server_type=server.server_type,
        command=server.command,
        args=tuple(
            _expand_agent_plugin_mcp_value(
                value,
                plugin_root=plugin_root,
                plugin_data=plugin_data,
            )
            for value in server.args
        ),
        env=tuple(
            (
                name,
                _expand_agent_plugin_mcp_value(
                    value,
                    plugin_root=plugin_root,
                    plugin_data=plugin_data,
                ),
            )
            for name, value in server.env
        ),
        cwd=(
            _expand_agent_plugin_mcp_value(
                server.cwd,
                plugin_root=plugin_root,
                plugin_data=plugin_data,
            )
            if server.cwd is not None
            else None
        ),
        url=server.url,
        headers=server.headers,
        provenance=server_provenance,
    )
    return AgentPluginMCPPreparationSuccess(config=config)


def prepare_agent_plugin_mcp_servers(
    plugin: AgentPlugin,
    *,
    plugin_root: Path,
    plugin_data: Path,
) -> AgentPluginMCPPreparation:
    """Prepare immutable native MCP facts from one canonical Agent Plugin IR."""
    from apm_cli.models.dependency.native_mcp import (
        AgentPluginMCPPreparation,
        AgentPluginMCPProvenance,
    )

    provenance = AgentPluginMCPProvenance(
        specification_version=plugin.specification_version,
        plugin_name=plugin.identity.name,
        plugin_version=plugin.identity.version,
        source_root=plugin.root,
        manifest=plugin.manifest,
    )
    root_value = str(plugin_root)
    data_value = str(plugin_data)
    results = tuple(
        _prepare_agent_plugin_mcp_server(
            server,
            provenance,
            plugin_root=root_value,
            plugin_data=data_value,
        )
        for server in plugin.components.mcp_servers
    )
    return AgentPluginMCPPreparation(provenance=provenance, results=results)
