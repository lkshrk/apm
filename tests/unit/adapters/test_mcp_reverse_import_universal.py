from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from apm_cli.adapters.client.claude import ClaudeClientAdapter
from apm_cli.adapters.client.hermes import HermesClientAdapter
from apm_cli.adapters.client.opencode import OpenCodeClientAdapter
from apm_cli.factory import ClientFactory
from apm_cli.importing.mcp_discovery import (
    discover_mcp_sources,
    validate_mcp_import_coverage,
)
from apm_cli.importing.service import _discover_mcp_targets
from apm_cli.integration.mcp_integrator import MCPIntegrator
from apm_cli.models.dependency.mcp import MCPDependency

_NATIVE_CASES = {
    "antigravity": {
        "httpUrl": "https://example.test/mcp",
        "headers": {"Authorization": "${TOKEN}"},
        "timeout": 30,
    },
    "claude": {
        "type": "stdio",
        "command": "uvx",
        "args": ["demo"],
        "env": {"TOKEN": "${TOKEN}"},
        "disabled": True,
    },
    "codex": {
        "url": "https://example.test/mcp",
        "http_headers": {"Authorization": "${env:TOKEN}"},
        "enabled": False,
    },
    "copilot": {
        "type": "http",
        "url": "https://example.test/mcp",
        "headers": {"Authorization": "${TOKEN}"},
        "tools": ["search"],
    },
    "cursor": {
        "type": "stdio",
        "command": "uvx",
        "args": ["demo"],
        "env": {"TOKEN": "${TOKEN}"},
    },
    "gemini": {
        "url": "https://example.test/events",
        "headers": {"Authorization": "${TOKEN}"},
        "excludeTools": ["dangerous"],
    },
    "hermes": {
        "command": "uvx",
        "args": ["demo"],
        "env": {"TOKEN": "${TOKEN}"},
        "enabled": False,
    },
    "intellij": {
        "type": "local",
        "command": "uvx",
        "args": ["demo"],
        "env": {"TOKEN": "${env:TOKEN}"},
    },
    "kiro": {
        "command": "uvx",
        "args": ["demo"],
        "env": {"TOKEN": "${TOKEN}"},
        "disabled": True,
        "autoApprove": ["search"],
    },
    "opencode": {
        "type": "local",
        "command": ["uvx", "demo"],
        "environment": {"TOKEN": "${TOKEN}"},
        "enabled": False,
    },
    "vscode": {
        "type": "streamable-http",
        "url": "https://example.test/mcp",
        "headers": {"Authorization": "${env:TOKEN}"},
        "disabled": True,
    },
    "windsurf": {
        "type": "local",
        "command": "uvx",
        "args": ["demo"],
        "env": {"TOKEN": "${TOKEN}"},
    },
}


@pytest.mark.parametrize("client", sorted(_NATIVE_CASES))
def test_every_registered_adapter_decodes_native_mcp(client, tmp_path):
    adapter = ClientFactory.create_client(client, project_root=tmp_path, user_scope=False)
    native = _NATIVE_CASES[client]
    expected_native = deepcopy(native)

    decoded = adapter.decode_server_config("demo", native)

    assert decoded["transport"] == (
        "stdio"
        if "command" in native
        else "sse"
        if client == "gemini"
        else "streamable-http"
        if client in {"antigravity", "vscode"}
        else "http"
    )
    assert native == expected_native
    if "env" in native or "environment" in native:
        assert decoded["env"] == native.get("env", native.get("environment"))
    if "headers" in native or "http_headers" in native:
        assert decoded["headers"] == native.get("headers", native.get("http_headers"))
    for extra in ("autoApprove", "disabled", "enabled", "excludeTools", "timeout"):
        if extra in native:
            assert decoded[extra] == native[extra]


def _render_native(adapter, decoded):
    dep = MCPDependency.from_dict({"name": "demo", "registry": False, **decoded})
    rendered = adapter.render_server_config(MCPIntegrator._build_self_defined_info(dep))
    if isinstance(adapter, OpenCodeClientAdapter):
        return adapter._to_opencode_format(rendered)
    if isinstance(adapter, HermesClientAdapter):
        return adapter._to_hermes_format(rendered)
    if isinstance(adapter, ClaudeClientAdapter):
        return adapter._normalize_mcp_entry_for_claude_code(rendered)
    return rendered


@pytest.mark.parametrize("client", sorted(_NATIVE_CASES))
def test_decode_render_decode_converges_for_every_registered_adapter(client, tmp_path):
    adapter = ClientFactory.create_client(client, project_root=tmp_path, user_scope=False)
    first = adapter.decode_server_config("demo", _NATIVE_CASES[client])

    second = adapter.decode_server_config("demo", _render_native(adapter, first))
    third = adapter.decode_server_config("demo", _render_native(adapter, second))

    assert third == second


def test_adapter_matrix_calls_registry_coverage_ratchet():
    validate_mcp_import_coverage(_NATIVE_CASES)
    assert set(_NATIVE_CASES) == set(ClientFactory.supported_clients())


def test_generic_decoder_keeps_only_safe_manifest_extras(tmp_path):
    adapter = ClientFactory.create_client("copilot", project_root=tmp_path)

    assert adapter.decode_server_config("demo", "not-a-mapping") == {
        "unsupported_reason": "malformed-mcp-server-config"
    }
    assert adapter.decode_server_config(
        "demo",
        {"name": "override", "registry": "override", "command": "uvx", "timeout": 30},
    ) == {"transport": "stdio", "command": "uvx", "timeout": 30}


def _tree_state(root: Path) -> dict[str, tuple[int, int, int, bytes | None]]:
    return {
        path.relative_to(root).as_posix(): (
            path.stat().st_mode,
            path.stat().st_mtime_ns,
            path.stat().st_size,
            path.read_bytes() if path.is_file() else None,
        )
        for path in [root, *sorted(root.rglob("*"))]
    }


def test_vscode_import_path_is_project_explicit_and_scan_read_only(tmp_path):
    project = tmp_path / "project"
    config = project / ".vscode" / "mcp.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps({"servers": {"demo": {"type": "stdio", "command": "uvx"}}}),
        encoding="utf-8",
    )
    before = _tree_state(project)

    assert discover_mcp_sources(["vscode"]) == []
    sources = discover_mcp_sources(["vscode"], project_root=project)

    assert [source.path for source in sources] == [config.resolve()]
    assert sources[0].servers["demo"]["transport"] == "stdio"
    assert _tree_state(project) == before


def test_global_mcp_discovery_never_initializes_the_http_cache(tmp_path, monkeypatch):
    home = tmp_path / "home"
    cache = tmp_path / "cache"
    config = tmp_path / "config"
    for root in (home, cache, config):
        root.mkdir()
    sentinel = cache / "keep"
    sentinel.write_text("unchanged", encoding="utf-8")
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.setenv("XDG_CACHE_HOME", os.fspath(cache))
    monkeypatch.setenv("XDG_CONFIG_HOME", os.fspath(config))
    monkeypatch.setenv("MCP_REGISTRY_URL", "not-a-url")
    before = _tree_state(cache)

    assert discover_mcp_sources() == []

    assert _tree_state(cache) == before
    assert not (cache / "apm" / "http_v1").exists()


def test_vscode_write_path_still_creates_its_parent(tmp_path):
    adapter = ClientFactory.create_client("vscode", project_root=tmp_path)
    config = {"servers": {"demo": {"type": "stdio", "command": "uvx"}}}

    assert not (tmp_path / ".vscode").exists()
    assert adapter.update_config(config) is True
    assert json.loads((tmp_path / ".vscode" / "mcp.json").read_text()) == config


def test_intellij_user_scan_redacts_literals_without_writes(tmp_path, monkeypatch):
    config_root = tmp_path / "config"
    config = config_root / "github-copilot" / "intellij" / "mcp.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "servers": {
                    "demo": {
                        "type": "local",
                        "command": "uvx",
                        "env": {"LITERAL": "secret", "SAFE": "${SAFE}"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("XDG_CONFIG_HOME", os.fspath(config_root))
    before = _tree_state(config_root)

    candidates, _ = _discover_mcp_targets(["intellij"])

    assert candidates[0]["secret_blocked"] is True
    assert candidates[0]["payload"]["env"] == {
        "LITERAL": {"blocked": "literal-secret"},
        "SAFE": "${SAFE}",
    }
    assert _tree_state(config_root) == before


def test_opencode_project_source_uses_native_mcp_key(tmp_path):
    config = tmp_path / "opencode.json"
    config.write_text(
        json.dumps(
            {
                "mcp": {
                    "demo": {
                        "type": "local",
                        "command": ["uvx", "demo"],
                        "environment": {},
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    sources = discover_mcp_sources(["opencode"], project_root=tmp_path)

    assert sources[0].servers["demo"]["command"] == "uvx"
    assert sources[0].servers["demo"]["args"] == ["demo"]
