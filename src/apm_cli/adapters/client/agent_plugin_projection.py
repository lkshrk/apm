"""Typed client projection from canonical Agent Plugin IR."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from ...agent_plugins.ir import (
    AgentPlugin,
    AgentPluginMcpServer,
    AgentPluginSkill,
    McpServerType,
)
from .base import MCPClientAdapter


class ClientProjectionCapability(str, Enum):
    """Portable Agent Plugin capabilities projected by client adapters."""

    MCP_STDIO = "mcp.stdio"
    MCP_STREAMABLE_HTTP = "mcp.streamable-http"
    MCP_SSE = "mcp.sse"
    SKILLS = "skills"


class ClientProjectionDiagnosticCode(str, Enum):
    """Stable codes for unsupported client projection outcomes."""

    RUNTIME_ENV_UNSUPPORTED = "client.runtime-env.unsupported"
    TRANSPORT_UNSUPPORTED = "client.transport.unsupported"


@dataclass(frozen=True, slots=True)
class ClientProjectionDiagnostic:
    """One typed unsupported-capability outcome."""

    code: ClientProjectionDiagnosticCode
    target: str
    capability: ClientProjectionCapability
    component: str
    message: str


@dataclass(frozen=True, slots=True)
class ProjectedMcpServer:
    """One canonical MCP server rendered to a client-native mapping."""

    name: str
    config: dict[str, Any]


@dataclass(frozen=True, slots=True)
class AgentPluginClientProjection:
    """Complete projection result with no unaccounted canonical components."""

    target: str
    skills: tuple[AgentPluginSkill, ...]
    mcp_servers: tuple[ProjectedMcpServer, ...]
    diagnostics: tuple[ClientProjectionDiagnostic, ...]

    @property
    def is_complete(self) -> bool:
        """Return whether every canonical component rendered successfully."""
        return not self.diagnostics


def _capability(server: AgentPluginMcpServer) -> ClientProjectionCapability:
    return {
        McpServerType.STDIO: ClientProjectionCapability.MCP_STDIO,
        McpServerType.STREAMABLE_HTTP: ClientProjectionCapability.MCP_STREAMABLE_HTTP,
        McpServerType.SSE: ClientProjectionCapability.MCP_SSE,
    }[server.server_type]


def _server_info(server: AgentPluginMcpServer) -> dict[str, Any]:
    if server.server_type is McpServerType.STDIO:
        return {
            "name": server.name,
            "_raw_stdio": {
                "command": server.command,
                "args": list(server.args),
                "env": dict(server.env),
                "cwd": server.cwd,
            },
        }
    return {
        "name": server.name,
        "remotes": [
            {
                "transport_type": server.server_type.value,
                "url": server.url,
                "headers": [{"name": name, "value": value} for name, value in server.headers],
            }
        ],
        "packages": [],
    }


def _runtime_env_diagnostic(
    adapter: MCPClientAdapter,
    server: AgentPluginMcpServer,
) -> ClientProjectionDiagnostic | None:
    if adapter.supports_runtime_env_substitution:
        return None
    if not server.env and not server.headers:
        return None
    return ClientProjectionDiagnostic(
        code=ClientProjectionDiagnosticCode.RUNTIME_ENV_UNSUPPORTED,
        target=adapter.target_name,
        capability=_capability(server),
        component=f"mcp:{server.name}",
        message=(
            f"{adapter.target_name} cannot safely project runtime environment references "
            f"for MCP server {server.name!r} without explicit resolved values."
        ),
    )


def project_agent_plugin_for_client(
    plugin: AgentPlugin,
    adapter: MCPClientAdapter,
) -> AgentPluginClientProjection:
    """Project canonical components or return one typed diagnostic per omission."""
    rendered: list[ProjectedMcpServer] = []
    diagnostics: list[ClientProjectionDiagnostic] = []
    for server in plugin.components.mcp_servers:
        env_diagnostic = _runtime_env_diagnostic(adapter, server)
        if env_diagnostic is not None:
            diagnostics.append(env_diagnostic)
            continue
        try:
            config = adapter.render_server_config(_server_info(server))
        except ValueError:
            diagnostics.append(
                ClientProjectionDiagnostic(
                    code=ClientProjectionDiagnosticCode.TRANSPORT_UNSUPPORTED,
                    target=adapter.target_name,
                    capability=_capability(server),
                    component=f"mcp:{server.name}",
                    message=(
                        f"{adapter.target_name} cannot represent MCP server "
                        f"{server.name!r} with {server.server_type.value} transport."
                    ),
                )
            )
            continue
        if not config:
            diagnostics.append(
                ClientProjectionDiagnostic(
                    code=ClientProjectionDiagnosticCode.TRANSPORT_UNSUPPORTED,
                    target=adapter.target_name,
                    capability=_capability(server),
                    component=f"mcp:{server.name}",
                    message=(
                        f"{adapter.target_name} produced no configuration for MCP server "
                        f"{server.name!r}."
                    ),
                )
            )
            continue
        rendered.append(ProjectedMcpServer(name=server.name, config=config))

    if len(rendered) + len(diagnostics) != len(plugin.components.mcp_servers):
        raise AssertionError("Client projection left canonical MCP components unaccounted")
    return AgentPluginClientProjection(
        target=adapter.target_name,
        skills=plugin.components.skills,
        mcp_servers=tuple(rendered),
        diagnostics=tuple(diagnostics),
    )


__all__ = [
    "AgentPluginClientProjection",
    "ClientProjectionCapability",
    "ClientProjectionDiagnostic",
    "ClientProjectionDiagnosticCode",
    "ProjectedMcpServer",
    "project_agent_plugin_for_client",
]
