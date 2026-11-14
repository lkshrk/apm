"""Client adapters keep env/header values as references at user scope."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest
import tomlkit

from apm_cli.adapters.client import codex as codex_module
from apm_cli.adapters.client.claude import ClaudeClientAdapter
from apm_cli.adapters.client.codex import CodexClientAdapter
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


@pytest.fixture(autouse=True)
def _codex_home(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))


def _codex_toml_text(tmp_path: Path) -> str:
    path = tmp_path / "codex" / "config.toml"
    return path.read_text() if path.exists() else ""


def _codex_stdio_info(env):
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
    return MCPIntegrator._build_self_defined_info(dep)


def _codex_http_info(headers):
    dep = MCPDependency.from_dict(
        {
            "name": "example",
            "registry": False,
            "transport": "http",
            "url": "https://example.test/mcp",
            "headers": headers,
        }
    )
    return MCPIntegrator._build_self_defined_info(dep)


def _codex_registry_info(env_vars):
    return {
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


def _try_configure_codex(tmp_path, info) -> tuple[bool, str]:
    messages: list[str] = []

    def record(message, **_):
        messages.append(message)

    adapter = CodexClientAdapter(project_root=tmp_path / "project", user_scope=True)
    with (
        mock.patch.object(codex_module, "_rich_error", side_effect=record, create=True),
        mock.patch.object(codex_module, "_rich_warning", side_effect=record),
    ):
        ok = adapter.configure_mcp_server("example", server_info_cache={"example": info})
    return ok, "\n".join([*messages, _codex_toml_text(tmp_path)])


def _codex_entry(tmp_path, info) -> dict:
    ok, _ = _try_configure_codex(tmp_path, info)
    assert ok
    return tomlkit.parse(_codex_toml_text(tmp_path))["mcp_servers"]["example"].unwrap()


def _configure_codex_stdio(tmp_path, env):
    return _codex_entry(tmp_path, _codex_stdio_info(env))


def _try_configure_codex_stdio(tmp_path, env):
    return _try_configure_codex(tmp_path, _codex_stdio_info(env))


def _configure_codex_http(tmp_path, headers):
    return _codex_entry(tmp_path, _codex_http_info(headers))


def _try_configure_codex_http(tmp_path, headers):
    return _try_configure_codex(tmp_path, _codex_http_info(headers))


def test_codex_user_scope_forwards_exact_reference(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_PAT", "s3cret-value")
    entry = _configure_codex_stdio(tmp_path, env={"GITHUB_PAT": "${GITHUB_PAT}"})
    assert entry["env_vars"] == ["GITHUB_PAT"]
    assert "env" not in entry
    assert "s3cret-value" not in _codex_toml_text(tmp_path)


def test_codex_user_scope_renamed_reference_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_PAT", "s3cret-value")
    ok, text = _try_configure_codex_stdio(tmp_path, env={"TOKEN": "${GITHUB_PAT}"})
    assert ok is False
    assert "s3cret-value" not in text
    assert "Codex cannot keep a secret reference for example env TOKEN" in text


def test_codex_user_scope_composite_env_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_PAT", "s3cret-value")
    ok, text = _try_configure_codex_stdio(
        tmp_path, env={"GITHUB_PAT": "${GITHUB_PAT}", "AUTH": "token <GITHUB_PAT>"}
    )
    assert ok is False
    assert "s3cret-value" not in text
    assert _codex_toml_text(tmp_path) == ""


def test_codex_user_scope_unexpressible_header_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("X", "s3cret-value")
    ok, text = _try_configure_codex_http(tmp_path, headers={"authorization": "token ${X}"})
    assert ok is False and "s3cret-value" not in text


def test_codex_user_scope_bearer_header_uses_env_var(tmp_path, monkeypatch):
    monkeypatch.setenv("X", "s3cret-value")
    entry = _configure_codex_http(tmp_path, headers={"Authorization": "Bearer ${X}"})
    assert entry["bearer_token_env_var"] == "X"


def test_codex_user_scope_whole_value_header_uses_env_http_headers(tmp_path, monkeypatch):
    monkeypatch.setenv("LITELLM_API", "s3cret-value")
    entry = _configure_codex_http(tmp_path, headers={"x-litellm-api-key": "${LITELLM_API}"})
    assert entry["env_http_headers"] == {"x-litellm-api-key": "LITELLM_API"}
    assert "s3cret-value" not in _codex_toml_text(tmp_path)


def test_codex_user_scope_plain_literal_env_kept(tmp_path):
    entry = _configure_codex_stdio(tmp_path, env={"MODE": "fast"})
    assert entry["env"] == {"MODE": "fast"}


def test_codex_user_scope_registry_env_list_forwarded_by_name(tmp_path, monkeypatch):
    monkeypatch.setenv("API_TOKEN", "s3cret-value")
    monkeypatch.setattr("rich.prompt.Prompt.ask", _fail_if_called)
    entry = _codex_entry(tmp_path, _codex_registry_info([{"name": "API_TOKEN", "required": True}]))
    assert entry["env_vars"] == ["API_TOKEN"]
    assert "API_TOKEN" not in entry.get("env", {})
    assert "s3cret-value" not in _codex_toml_text(tmp_path)


def test_codex_user_scope_never_prompts(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_PAT", raising=False)
    monkeypatch.setattr("rich.prompt.Prompt.ask", _fail_if_called)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    adapter = CodexClientAdapter(project_root=tmp_path / "project", user_scope=True)
    assert adapter._should_skip_env_prompts({}) is True


def test_codex_user_scope_docker_registry_env_forwarded_with_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("API_TOKEN", "s3cret-value")
    info = {
        "name": "example",
        "packages": [
            {
                "registry_name": "docker",
                "name": "example/image",
                "environment_variables": [{"name": "API_TOKEN", "required": True}],
            }
        ],
    }
    entry = _codex_entry(tmp_path, info)
    assert entry["env_vars"] == ["API_TOKEN"]
    assert entry["args"][-3:-1] == ["-e", "API_TOKEN"]
    assert "s3cret-value" not in _codex_toml_text(tmp_path)
