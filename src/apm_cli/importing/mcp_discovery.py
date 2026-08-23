"""Factory-driven MCP import source selection."""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

try:
    import tomllib
except ImportError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

from apm_cli.factory import ClientFactory

from .discovery import path_boundary_error


@dataclass(frozen=True)
class MCPSource:
    """One existing adapter-owned MCP configuration document."""

    client: str
    adapter: Any
    path: Path
    servers: dict[str, Any]
    scope: str = "global"
    project_root: Path | None = None
    blocked_reason: str | None = None


def _valid_document(path: Path) -> bool:
    raw = path.read_bytes()
    if path.suffix == ".json":
        return isinstance(json.loads(raw), dict)
    if path.suffix == ".toml":
        return isinstance(tomllib.loads(raw.decode("utf-8")), dict)
    if path.suffix in {".yaml", ".yml"}:
        import yaml

        return isinstance(yaml.safe_load(raw), dict)
    return True


def discover_mcp_sources(
    clients: Iterable[str] | None = None,
    *,
    project_root: Path | None = None,
) -> list[MCPSource]:
    """Read applicable MCP sources solely through the canonical factory."""
    scope = "project" if project_root is not None else "global"
    canonical_root = project_root.resolve(strict=True) if project_root is not None else None
    selected = set(clients or ClientFactory.supported_clients())
    sources: list[MCPSource] = []
    for client in sorted(ClientFactory.supported_clients() & selected):
        try:
            probe = ClientFactory.create_client(
                client,
                project_root=project_root,
                user_scope=scope == "global",
            )
            if scope == "global" and not probe.supports_user_scope:
                continue
            path_getter = getattr(probe, "get_import_config_path", probe.get_config_path)
            raw_path = Path(os.path.abspath(Path(path_getter()).expanduser()))
        except (OSError, ValueError):
            fallback = canonical_root or Path.home()
            sources.append(
                MCPSource(
                    client,
                    None,
                    fallback,
                    {},
                    scope,
                    canonical_root,
                    "source-resolver-error",
                )
            )
            continue
        if canonical_root is not None and not raw_path.is_relative_to(canonical_root):
            continue
        boundary_root = canonical_root or (
            Path.home() if raw_path.is_relative_to(Path.home()) else Path(raw_path.anchor)
        )
        if error := path_boundary_error(boundary_root, raw_path):
            sources.append(MCPSource(client, probe, raw_path, {}, scope, canonical_root, error))
            continue
        if not raw_path.is_file():
            continue
        try:
            if not _valid_document(raw_path):
                raise ValueError
            document = probe.get_current_config()
        except (OSError, RuntimeError, UnicodeError, ValueError, yaml.YAMLError):
            sources.append(
                MCPSource(
                    client,
                    probe,
                    raw_path,
                    {},
                    scope,
                    canonical_root,
                    "malformed-or-unreadable-mcp-document",
                )
            )
            continue
        servers = document.get(probe.mcp_servers_key, {}) if isinstance(document, dict) else {}
        if not isinstance(document, dict) or not isinstance(servers, dict):
            sources.append(
                MCPSource(
                    client,
                    probe,
                    raw_path,
                    {},
                    scope,
                    canonical_root,
                    "malformed-or-unreadable-mcp-document",
                )
            )
            continue
        decode = getattr(probe, "decode_server_config", None)
        try:
            normalized = (
                {name: decode(name, native) for name, native in servers.items()}
                if callable(decode)
                else servers
            )
        except (OSError, TypeError, ValueError):
            sources.append(
                MCPSource(
                    client,
                    probe,
                    raw_path,
                    {},
                    scope,
                    canonical_root,
                    "malformed-mcp-server-config",
                )
            )
            continue
        sources.append(MCPSource(client, probe, raw_path, normalized, scope, canonical_root))
    return sources


def validate_mcp_import_coverage(covered_clients: Iterable[str]) -> None:
    """Fail when the adapter registry grows without reverse-import coverage."""
    missing = sorted(ClientFactory.supported_clients() - set(covered_clients))
    if missing:
        raise ValueError(f"missing MCP import coverage: {', '.join(missing)}")
