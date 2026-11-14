"""Claude keeps env/header values as references at user scope."""

from __future__ import annotations

import json
from pathlib import Path

from apm_cli.adapters.client.claude import ClaudeClientAdapter
from apm_cli.integration.mcp_integrator import MCPIntegrator
from apm_cli.models.dependency.mcp import MCPDependency


def _adapter(tmp_path: Path, monkeypatch, user_scope: bool = True) -> ClaudeClientAdapter:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.setattr(Path, "home", lambda: home)
    return ClaudeClientAdapter(project_root=tmp_path / "project", user_scope=user_scope)


def _claude_json_text(tmp_path: Path) -> str:
    return (tmp_path / "home" / ".claude.json").read_text()


def _written_entry(tmp_path: Path, name: str = "example") -> dict:
    return json.loads(_claude_json_text(tmp_path))["mcpServers"][name]


def _configure(tmp_path, monkeypatch, info) -> dict:
    adapter = _adapter(tmp_path, monkeypatch)
    assert adapter.configure_mcp_server("example", server_info_cache={"example": info})
    return _written_entry(tmp_path)


def _configure_claude_stdio(tmp_path, monkeypatch, env):
    dep = MCPDependency.from_dict(
        {
            "name": "example",
            "registry": False,
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "some-server"],
            "env": env,
        }
    )
    return _configure(tmp_path, monkeypatch, MCPIntegrator._build_self_defined_info(dep))


def _configure_claude_http(tmp_path, monkeypatch, headers):
    dep = MCPDependency.from_dict(
        {
            "name": "example",
            "registry": False,
            "transport": "http",
            "url": "https://example.test/mcp",
            "headers": headers,
        }
    )
    return _configure(tmp_path, monkeypatch, MCPIntegrator._build_self_defined_info(dep))


def _configure_claude_registry(tmp_path, monkeypatch, env_vars):
    info = {
        "name": "example",
        "packages": [
            {
                "registry_name": "npm",
                "name": "some-server",
                "runtime_hint": "npx",
                "environment_variables": env_vars,
            }
        ],
    }
    return _configure(tmp_path, monkeypatch, info)


def _fail_if_called(*args, **kwargs):
    raise AssertionError("prompted for a value")


def test_claude_user_scope_stdio_env_stays_reference(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_PAT", "s3cret-value")
    entry = _configure_claude_stdio(tmp_path, monkeypatch, env={"GITHUB_PAT": "${GITHUB_PAT}"})
    assert entry["env"] == {"GITHUB_PAT": "${GITHUB_PAT}"}
    assert "s3cret-value" not in _claude_json_text(tmp_path)


def test_claude_user_scope_header_stays_reference(tmp_path, monkeypatch):
    monkeypatch.setenv("LITELLM_API", "s3cret-value")
    entry = _configure_claude_http(
        tmp_path, monkeypatch, headers={"x-litellm-api-key": "${LITELLM_API}"}
    )
    assert entry["headers"] == {"x-litellm-api-key": "${LITELLM_API}"}
    assert "s3cret-value" not in _claude_json_text(tmp_path)


def test_claude_user_scope_registry_env_list_becomes_reference(tmp_path, monkeypatch):
    monkeypatch.setenv("API_TOKEN", "s3cret-value")
    entry = _configure_claude_registry(
        tmp_path, monkeypatch, env_vars=[{"name": "API_TOKEN", "required": True}]
    )
    assert entry["env"]["API_TOKEN"] == "${API_TOKEN}"
    assert "s3cret-value" not in _claude_json_text(tmp_path)


def test_claude_user_scope_never_prompts(tmp_path, monkeypatch):
    monkeypatch.delenv("API_TOKEN", raising=False)
    monkeypatch.setattr("rich.prompt.Prompt.ask", _fail_if_called)
    entry = _configure_claude_registry(
        tmp_path, monkeypatch, env_vars=[{"name": "API_TOKEN", "required": True}]
    )
    assert entry["env"]["API_TOKEN"] == "${API_TOKEN}"


def test_claude_project_scope_unchanged(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_PAT", "value")
    adapter = ClaudeClientAdapter(project_root=tmp_path, user_scope=False)
    assert adapter._supports_runtime_env_substitution is False
    assert (
        ClaudeClientAdapter(
            project_root=tmp_path, user_scope=True
        )._supports_runtime_env_substitution
        is True
    )
