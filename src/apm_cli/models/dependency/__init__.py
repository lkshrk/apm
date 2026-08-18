"""Dependency reference models and Git reference utilities."""

from .lsp import LSPDependency
from .mcp import MCPDependency
from .native_mcp import (
    AgentPluginMCPPreparation,
    AgentPluginMCPPreparationFailure,
    AgentPluginMCPPreparationResult,
    AgentPluginMCPPreparationSuccess,
    AgentPluginMCPProvenance,
    AgentPluginMCPServerConfig,
    AgentPluginMCPServerProvenance,
)
from .reference import DependencyReference
from .types import (
    GitReferenceType,
    RemoteRef,
    ResolvedReference,
    VirtualPackageType,
    parse_git_reference,
)

__all__ = [
    "AgentPluginMCPPreparation",
    "AgentPluginMCPPreparationFailure",
    "AgentPluginMCPPreparationResult",
    "AgentPluginMCPPreparationSuccess",
    "AgentPluginMCPProvenance",
    "AgentPluginMCPServerConfig",
    "AgentPluginMCPServerProvenance",
    "DependencyReference",
    "GitReferenceType",
    "LSPDependency",
    "MCPDependency",
    "RemoteRef",
    "ResolvedReference",
    "VirtualPackageType",
    "parse_git_reference",
]
