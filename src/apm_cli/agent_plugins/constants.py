"""Canonical Agent Plugins v1.0.0 constants."""

from __future__ import annotations

AGENT_PLUGINS_VERSION = "1.0.0"
AGENT_PLUGINS_SCHEMA_PREFIX = "https://agent-plugins.org/schemas/"
PLUGIN_SCHEMA_ID = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
MCP_SCHEMA_ID = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"

COM_MICROSOFT_APM_NAMESPACE = "com.microsoft.apm"
COM_MICROSOFT_APM_SCHEMA_VERSION = "1"

SUPPORTED_PLUGIN_SCHEMA_IDS = frozenset({PLUGIN_SCHEMA_ID})
SUPPORTED_MCP_SCHEMA_IDS = frozenset({MCP_SCHEMA_ID})
