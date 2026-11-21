"""Client adapters keep env/header values as references at user scope."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest
import tomlkit

from apm_cli.adapters.client.base import env_references
from apm_cli.adapters.client.claude import ClaudeClientAdapter
from apm_cli.adapters.client.codex import CodexClientAdapter
from apm_cli.adapters.client.opencode import OpenCodeClientAdapter
from apm_cli.core import null_logger
from apm_cli.core.safe_installer import SafeMCPInstaller
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


def test_claude_keeps_references_at_both_scopes(tmp_path):
    for user_scope in (False, True):
        adapter = ClaudeClientAdapter(project_root=tmp_path, user_scope=user_scope)
        assert adapter._supports_runtime_env_substitution is True


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
        mock.patch.object(null_logger, "_rich_error", side_effect=record),
        mock.patch.object(null_logger, "_rich_warning", side_effect=record),
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
    assert "use TOKEN: ${TOKEN}" in text


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


@pytest.mark.parametrize("arg", ["${GITHUB_PAT}", "--token=${env:GITHUB_PAT}", "<GITHUB_PAT>"])
def test_codex_user_scope_stdio_arg_reference_is_refused(tmp_path, monkeypatch, arg):
    monkeypatch.setenv("GITHUB_PAT", "s3cret-value")
    info = _codex_stdio_info({"GITHUB_PAT": "${GITHUB_PAT}"})
    info["_raw_stdio"]["args"] = ["-y", "some-server", arg]
    ok, text = _try_configure_codex(tmp_path, info)
    assert ok is False
    assert "example args" in text
    assert "s3cret-value" not in text
    assert _codex_toml_text(tmp_path) == ""


def test_codex_user_scope_registry_arg_reference_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("API_TOKEN", "s3cret-value")
    info = _codex_registry_info([{"name": "API_TOKEN", "required": True}])
    info["packages"][0]["package_arguments"] = [
        {"type": "positional", "value": "--token=<API_TOKEN>"}
    ]
    ok, text = _try_configure_codex(tmp_path, info)
    assert ok is False
    assert "example args" in text
    assert "s3cret-value" not in text
    assert _codex_toml_text(tmp_path) == ""


@pytest.fixture
def _user_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.setattr(Path, "home", lambda: home)
    return home


def _stdio_info(name, env):
    dep = MCPDependency.from_dict(
        {
            "name": name,
            "registry": False,
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "some-server"],
            "env": env,
        }
    )
    return MCPIntegrator._build_self_defined_info(dep)


def _install(tmp_path, runtime, servers):
    installer = SafeMCPInstaller(runtime, project_root=tmp_path / "project", user_scope=True)
    cache = {name: _stdio_info(name, env) for name, env in servers.items()}
    return installer.install_servers(list(servers), server_info_cache=cache)


def _install_one(tmp_path, runtime, env):
    return _install(tmp_path, runtime, {"example": env})


def _all_written_text(tmp_path: Path) -> str:
    return "\n".join(
        p.read_text(errors="replace") for p in sorted(tmp_path.rglob("*")) if p.is_file()
    )


def _configure_opencode_stdio(tmp_path, env):
    adapter = OpenCodeClientAdapter(project_root=tmp_path / "project", user_scope=True)
    info = _stdio_info("example", env)
    assert adapter.configure_mcp_server("example", server_info_cache={"example": info})
    path = Path(adapter.get_config_path())
    assert "s3cret-value" not in path.read_text()
    return json.loads(path.read_text())["mcp"]["example"]


@pytest.mark.usefixtures("_user_home")
@pytest.mark.parametrize("runtime", ["gemini", "hermes", "windsurf"])
def test_resolving_adapter_refuses_referencing_server(tmp_path, monkeypatch, runtime):
    monkeypatch.setenv("GITHUB_PAT", "s3cret-value")
    summary = _install_one(tmp_path, runtime, env={"GITHUB_PAT": "${GITHUB_PAT}"})
    assert summary.failed and not summary.installed
    assert summary.failed[0]["reason"] == f"{runtime} cannot keep secret references at user scope"
    assert "s3cret-value" not in _all_written_text(tmp_path)


@pytest.mark.usefixtures("_user_home")
@pytest.mark.parametrize("runtime", ["gemini", "hermes", "windsurf"])
def test_resolving_adapter_installs_server_without_references(tmp_path, runtime):
    summary = _install_one(tmp_path, runtime, env={"MODE": "fast"})
    assert summary.installed


@pytest.mark.usefixtures("_user_home")
@pytest.mark.parametrize("runtime", ["gemini", "hermes", "windsurf", "codex"])
def test_refused_server_does_not_stop_the_others(tmp_path, monkeypatch, runtime):
    monkeypatch.setenv("GITHUB_PAT", "s3cret-value")
    refused_env = (
        {"TOKEN": "${GITHUB_PAT}"} if runtime == "codex" else {"GITHUB_PAT": "${GITHUB_PAT}"}
    )
    summary = _install(
        tmp_path,
        runtime,
        {"first": {"MODE": "fast"}, "refused": refused_env, "last": {"MODE": "slow"}},
    )
    assert summary.installed == ["first", "last"]
    assert [item["server"] for item in summary.failed] == ["refused"]
    assert "s3cret-value" not in _all_written_text(tmp_path)


@pytest.mark.usefixtures("_user_home")
@pytest.mark.parametrize("runtime", ["claude", "codex", "opencode"])
def test_reference_writing_adapter_is_not_refused(tmp_path, monkeypatch, runtime):
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.setenv("GITHUB_PAT", "s3cret-value")
    summary = _install_one(tmp_path, runtime, env={"GITHUB_PAT": "${GITHUB_PAT}"})
    assert summary.installed == ["example"]
    assert "s3cret-value" not in _all_written_text(tmp_path)


def test_writes_env_references_per_adapter(tmp_path):
    root = tmp_path / "project"
    assert CodexClientAdapter(project_root=root, user_scope=True).writes_env_references()
    assert ClaudeClientAdapter(project_root=root, user_scope=True).writes_env_references()
    assert ClaudeClientAdapter(project_root=root, user_scope=False).writes_env_references()


@pytest.mark.usefixtures("_user_home")
def test_opencode_user_scope_writes_env_placeholder(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_PAT", "s3cret-value")
    entry = _configure_opencode_stdio(tmp_path, env={"GITHUB_PAT": "${GITHUB_PAT}"})
    assert entry["environment"]["GITHUB_PAT"] == "{env:GITHUB_PAT}"


def test_env_references_collects_all_sources():
    info = {
        "_raw_stdio": {"env": {"A": "${A}"}, "args": ["--t=${B}"]},
        "remotes": [{"headers": [{"name": "H", "value": "Bearer ${C}"}]}],
    }
    assert env_references(info) == {"A", "B", "C"}


def test_env_references_includes_registry_env_names_and_ignores_literals():
    info = {
        "_raw_stdio": {"env": {"MODE": "fast"}, "args": ["-y", "<D>"]},
        "remotes": [{"headers": [{"name": "X", "value": "${env:E}"}]}],
    }
    assert env_references(info) == {"D", "E"}
    assert env_references(_codex_registry_info([{"name": "F"}])) == {"F"}
    assert env_references(_stdio_info("example", {"MODE": "fast"})) == set()


@pytest.mark.parametrize(
    ("headers", "expected"),
    [({"X-Mode": "fast"}, set()), ({"X-Key": "${X}"}, {"X"})],
)
def test_env_references_accepts_mapping_headers(headers, expected):
    assert env_references({"remotes": [{"headers": headers}]}) == expected


@pytest.mark.usefixtures("_user_home")
@pytest.mark.parametrize("runtime", ["hermes", "windsurf"])
def test_mapping_header_server_installs_beside_others(tmp_path, runtime):
    installer = SafeMCPInstaller(runtime, project_root=tmp_path / "project", user_scope=True)
    remote = {"transport_type": "http", "url": "https://example.test/mcp"}
    info = {"name": "remote", "remotes": [{**remote, "headers": {"X-Mode": "fast"}}]}
    cache = {"remote": info, "local": _stdio_info("local", {"MODE": "fast"})}
    summary = installer.install_servers(["remote", "local"], server_info_cache=cache)
    assert summary.installed == ["remote", "local"]


@pytest.mark.usefixtures("_user_home")
@pytest.mark.parametrize("runtime", ["gemini", "hermes", "windsurf"])
def test_resolving_adapter_refuses_server_without_info(tmp_path, runtime):
    installer = SafeMCPInstaller(runtime, project_root=tmp_path / "project", user_scope=True)
    cache = {"unknown": None, "local": _stdio_info("local", {"MODE": "fast"})}
    summary = installer.install_servers(["unknown", "local"], server_info_cache=cache)
    assert summary.installed == ["local"]
    assert summary.failed == [
        {
            "server": "unknown",
            "reason": "server info for unknown unavailable; "
            "cannot verify it has no secret references",
        }
    ]


def _registry_operations(info):
    from apm_cli.registry.operations import MCPServerOperations

    operations = MCPServerOperations()
    operations.validate_servers_exist = mock.Mock(return_value=(["example"], []))
    operations.check_servers_needing_installation = mock.Mock(return_value=["example"])
    operations.batch_fetch_server_info = mock.Mock(return_value={"example": info})
    return operations


def test_user_scope_registry_install_never_looks_up_or_prompts(tmp_path, monkeypatch, _user_home):
    import os

    from apm_cli.integration.mcp_integrator_install import _install_registry_group

    real_getenv = os.getenv

    def guarded_getenv(name, *args):
        if name in {"API_TOKEN", "ADO_ORG"}:
            raise AssertionError(f"looked up {name}")
        return real_getenv(name, *args)

    for var in ("CI", "GITHUB_ACTIONS", "TRAVIS", "JENKINS_URL", "BUILDKITE", "APM_E2E_TESTS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.setenv("API_TOKEN", "s3cret-value")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr("rich.prompt.Prompt.ask", _fail_if_called)
    monkeypatch.setattr(os, "getenv", guarded_getenv)
    info = _codex_registry_info([{"name": "API_TOKEN", "required": True}])
    info["packages"][0]["package_arguments"] = [
        {
            "type": "named",
            "name": "--org",
            "value": "{ado_org}",
            "variables": {"ado_org": {"is_required": True, "is_secret": True}},
        }
    ]
    managed: dict[str, set[str]] = {}

    configured = _install_registry_group(
        operations=_registry_operations(info),
        group_dep_names=["example"],
        group_dep_map={},
        group_deps=["example"],
        target_runtimes=["claude"],
        stored_mcp_configs={},
        servers_to_update=set(),
        successful_updates=set(),
        project_root=tmp_path / "project",
        user_scope=True,
        verbose=False,
        console=None,
        logger=mock.MagicMock(),
        managed_target_servers=managed,
    )

    assert configured == 1
    assert managed == {"claude": {"example"}}
    assert _written_entry(tmp_path)["env"]["API_TOKEN"] == "${API_TOKEN}"
    assert "s3cret-value" not in _claude_json_text(tmp_path)


_GITHUB_TOKEN_VARS = (
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_APM_PAT",
    "GITHUB_COPILOT_PAT",
    "GITHUB_PERSONAL_ACCESS_TOKEN",
)


@pytest.mark.usefixtures("_user_home")
@pytest.mark.parametrize("runtime", ["hermes", "windsurf"])
def test_resolving_adapter_never_injects_github_token(tmp_path, monkeypatch, runtime):
    for name in _GITHUB_TOKEN_VARS:
        monkeypatch.setenv(name, "ghp_fake-s3cret")
    info = {
        "name": "github-mcp-server",
        "remotes": [{"transport_type": "http", "url": "https://api.githubcopilot.com/mcp/"}],
    }
    installer = SafeMCPInstaller(runtime, project_root=tmp_path / "project", user_scope=True)
    summary = installer.install_servers(
        ["github-mcp-server"], server_info_cache={"github-mcp-server": info}
    )
    written = _all_written_text(tmp_path)
    assert summary.installed == ["github-mcp-server"]
    assert "api.githubcopilot.com" in written
    assert "ghp_fake-s3cret" not in written


def test_codex_user_scope_stringifies_non_string_env_literals(tmp_path):
    entry = _configure_codex_stdio(tmp_path, env={"DEBUG": True, "PORT": 8080, "MODE": "fast"})
    assert entry["env"] == {"DEBUG": "True", "PORT": "8080", "MODE": "fast"}


def test_codex_user_scope_shell_default_env_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("V", "s3cret-value")
    ok, text = _try_configure_codex_stdio(tmp_path, env={"V": "${V:-x}"})
    assert ok is False
    assert "s3cret-value" not in text
    assert "Codex cannot keep a secret reference for example env V" in text
    assert _codex_toml_text(tmp_path) == ""


def test_claude_user_scope_keeps_manifest_literal(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_PAT", "s3cret-value")
    entry = _configure_claude_stdio(
        tmp_path, monkeypatch, env={"MODE": "fast", "GITHUB_PAT": "${GITHUB_PAT}"}
    )
    assert entry["env"] == {"MODE": "fast", "GITHUB_PAT": "${GITHUB_PAT}"}
    assert "s3cret-value" not in _claude_json_text(tmp_path)


def test_copilot_still_turns_manifest_literal_into_reference(tmp_path):
    from apm_cli.adapters.client.copilot import CopilotClientAdapter

    adapter = CopilotClientAdapter(project_root=tmp_path, user_scope=True)
    env = adapter._resolve_environment_variables({"MODE": "fast", "K": "${K}"})
    assert env == {"MODE": "${MODE}", "K": "${K}"}


@pytest.mark.usefixtures("_user_home")
def test_codex_refused_server_with_existing_entry_does_not_abort_install(tmp_path, monkeypatch):
    from apm_cli.core.null_logger import NullCommandLogger
    from apm_cli.integration.mcp_integrator_install import _install_self_defined_deps

    monkeypatch.setenv("OTHER", "s3cret-value")
    path = tmp_path / "codex" / "config.toml"
    path.parent.mkdir(parents=True)
    path.write_text('[mcp_servers.refused]\ncommand = "hand-written"\n')
    deps = [
        MCPDependency.from_dict(
            {"name": name, "registry": False, "transport": "stdio", "command": "npx", "env": env}
        )
        for name, env in (("refused", {"TOKEN": "${OTHER}"}), ("last", {"MODE": "fast"}))
    ]
    claims: dict[str, set[str]] = {"codex": {"refused"}}
    errors: list[str] = []

    with mock.patch.object(null_logger, "_rich_error", side_effect=lambda m, **_: errors.append(m)):
        configured = _install_self_defined_deps(
            deps,
            ["codex"],
            {},
            set(),
            set(),
            tmp_path / "project",
            True,
            False,
            None,
            NullCommandLogger(),
            claims,
        )

    servers = tomlkit.parse(_codex_toml_text(tmp_path))["mcp_servers"]
    assert configured == 1
    assert errors[0] == (
        "Codex cannot keep a secret reference for refused env TOKEN; use TOKEN: ${TOKEN}"
    )
    assert all("refused" in error for error in errors)
    assert servers["refused"]["command"] == "hand-written"
    assert servers["last"]["env"] == {"MODE": "fast"}
    assert "s3cret-value" not in _codex_toml_text(tmp_path)
