"""Immutable value models for native Agent Plugin MCP preparation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TypeAlias

from apm_cli.agent_plugins.ir import McpServerType, SourceProvenance


@dataclass(frozen=True, slots=True)
class AgentPluginMCPProvenance:
    """Canonical plugin identity and source provenance for native MCP state."""

    specification_version: str
    plugin_name: str
    plugin_version: str | None
    source_root: Path
    manifest: SourceProvenance


@dataclass(frozen=True, slots=True)
class AgentPluginMCPServerProvenance:
    """Exact ownership chain for one native Agent Plugin MCP server."""

    plugin: AgentPluginMCPProvenance
    declaration: SourceProvenance


@dataclass(frozen=True, slots=True)
class AgentPluginMCPServerConfig:
    """Immutable portable MCP facts prepared from canonical Agent Plugin IR."""

    name: str
    server_type: McpServerType
    command: str | None
    args: tuple[str, ...] = field(repr=False)
    env: tuple[tuple[str, str], ...] = field(repr=False)
    cwd: str | None
    url: str | None = field(repr=False)
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    provenance: AgentPluginMCPServerProvenance


@dataclass(frozen=True, slots=True)
class AgentPluginMCPPreparationSuccess:
    """One server whose native portable configuration was prepared."""

    config: AgentPluginMCPServerConfig

    @property
    def server_name(self) -> str:
        """Return the stable server identity."""
        return self.config.name

    @property
    def provenance(self) -> AgentPluginMCPServerProvenance:
        """Return the ownership facts that must accompany later writes."""
        return self.config.provenance


@dataclass(frozen=True, slots=True)
class AgentPluginMCPPreparationFailure:
    """Typed per-server failure for later transactional deployment handling."""

    server_name: str
    provenance: AgentPluginMCPServerProvenance
    code: str
    message: str = field(repr=False)


AgentPluginMCPPreparationResult: TypeAlias = (
    AgentPluginMCPPreparationSuccess | AgentPluginMCPPreparationFailure
)


@dataclass(frozen=True, slots=True)
class AgentPluginMCPPreparation:
    """Read-only native MCP preparation batch consumed by the T8 transaction."""

    provenance: AgentPluginMCPProvenance
    results: tuple[AgentPluginMCPPreparationResult, ...]

    @property
    def successes(self) -> tuple[AgentPluginMCPPreparationSuccess, ...]:
        """Return prepared servers without discarding per-server result shape."""
        return tuple(
            result
            for result in self.results
            if isinstance(result, AgentPluginMCPPreparationSuccess)
        )

    @property
    def failures(self) -> tuple[AgentPluginMCPPreparationFailure, ...]:
        """Return typed failures for partial-failure transaction policy."""
        return tuple(
            result
            for result in self.results
            if isinstance(result, AgentPluginMCPPreparationFailure)
        )
