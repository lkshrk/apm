"""Native omp files, runtime auth, and trust-boundary behavior."""

from __future__ import annotations

import copy
import json
import shlex
from pathlib import Path
from unittest.mock import patch

import pytest

from apm_cli.adapters.client.omp import OmpClientAdapter
from apm_cli.core.target_catalog import TARGET_CAPABILITIES, manifest_target_names
from apm_cli.factory import ClientFactory
from apm_cli.integration.mcp_integrator import MCPIntegrator
from apm_cli.integration.targets import KNOWN_TARGETS
from apm_cli.models.dependency.mcp import HEADER_HELPER_KEY, MCPDependency


def dependency(**overrides):
    return MCPDependency.from_dict(
        {
            "name": "example",
            "registry": False,
            "transport": "http",
            "url": "https://example.test/mcp",
            **overrides,
        }
    )


def test_native_registration_and_shared_skills():
    assert isinstance(ClientFactory.create_client("omp"), OmpClientAdapter)
    assert "omp" in manifest_target_names()
    assert not TARGET_CAPABILITIES["omp"].mcp_only
    assert TARGET_CAPABILITIES["omp"].explicit_only
    profile = KNOWN_TARGETS["omp"]
    assert profile.root_dir == ".omp"
    assert profile.user_root_dir == ".omp/agent"
    assert profile.skills_rel_root == ".agents/skills"
    assert set(profile.primitives) == {"skills", "extensions", "hooks"}
    assert not profile.detect_by_dir


@pytest.mark.parametrize(
    "override", [None, "", "relative/profile", "~/literal-profile", " profile "]
)
def test_default_profile_path_matches_omp(tmp_path, monkeypatch, override):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    if override is None:
        monkeypatch.delenv("PI_CODING_AGENT_DIR", raising=False)
    else:
        monkeypatch.setenv("PI_CODING_AGENT_DIR", override)
    adapter = OmpClientAdapter(project_root=tmp_path / "project", user_scope=True)
    expected = tmp_path / override if override else tmp_path / "home" / ".omp" / "agent"
    assert Path(adapter.get_config_path()) == expected / "mcp.json"
    scoped = KNOWN_TARGETS["omp"].for_scope(user_scope=True)
    assert (Path.home() / scoped.root_dir).resolve() == expected.resolve()
    assert scoped.skills_rel_root == ".agents/skills"
    project = OmpClientAdapter(project_root=tmp_path / "project")
    assert Path(project.get_config_path()) == tmp_path / "project" / ".omp" / "mcp.json"


def test_absolute_profile_override(tmp_path, monkeypatch):
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(tmp_path / "custom"))
    assert (
        Path(OmpClientAdapter(user_scope=True).get_config_path())
        == tmp_path / "custom" / "mcp.json"
    )


def test_writes_preserve_envelope_connections_and_local_controls(tmp_path):
    adapter = OmpClientAdapter(project_root=tmp_path)
    path = Path(adapter.get_config_path())
    path.parent.mkdir()
    initial = {
        "futureOption": {"nested": [1, 2]},
        "disabledServers": ["example"],
        "enabledServers": ["unrelated"],
        "mcpServers": {
            "unrelated": {"command": "personal-tool", "custom": True},
            "example": {
                "type": "http",
                "url": "https://old.test/mcp",
                "instructions": False,
                "enabled": False,
            },
        },
    }
    path.write_text(json.dumps(initial))
    dep = dependency()
    info = MCPIntegrator._build_self_defined_info(dep)
    assert adapter.configure_mcp_server(dep.name, server_info_cache={dep.name: info})
    actual = json.loads(path.read_text())
    assert actual == {
        **initial,
        "mcpServers": {
            **initial["mcpServers"],
            "example": {"type": "http", "url": dep.url, "instructions": False, "enabled": False},
        },
    }
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "content", ["not JSON", "[]", '{"mcpServers": []}', '{"mcpServers": null}']
)
def test_malformed_files_are_not_overwritten(tmp_path, content):
    adapter = OmpClientAdapter(project_root=tmp_path)
    path = Path(adapter.get_config_path())
    path.parent.mkdir()
    path.write_text(content)
    assert not adapter.validate_config_for_install()
    assert adapter.update_config({"example": {"command": "tool"}}) is False
    assert path.read_text() == content


def test_user_symlink_is_not_overwritten(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.delenv("PI_CODING_AGENT_DIR", raising=False)
    real = tmp_path / "native"
    real.mkdir()
    (home / ".omp").symlink_to(real, target_is_directory=True)
    adapter = OmpClientAdapter(user_scope=True)
    assert not adapter.validate_config_for_install()
    assert not adapter.update_config({"example": {"command": "tool"}})
    assert not (real / "agent" / "mcp.json").exists()


@pytest.mark.parametrize("helper_field", ["headersHelper", "http_headers_helper"])
def test_helpers_are_rendered_not_executed_and_keys_are_shell_quoted(tmp_path, helper_field):
    helper = "~/.config/example/headers --json"
    key = "X-O'Brien"
    dep = dependency(extra={helper_field: helper, "headersHelperKeys": [key]})
    info = MCPIntegrator._build_self_defined_info(dep)
    with (
        patch("subprocess.run", side_effect=AssertionError("helper must not execute")),
        patch("subprocess.check_output", side_effect=AssertionError("helper must not execute")),
    ):
        adapter = OmpClientAdapter(project_root=tmp_path)
        config = adapter.render_server_config(info)
        assert adapter.configure_mcp_server(dep.name, server_info_cache={dep.name: info})
    assert config["headers"] == {key: f"!{helper} | jq -er --arg key {shlex.quote(key)} '.[$key]'"}
    assert "headersHelperKeys" not in config
    assert helper_field not in config
    assert json.loads(Path(adapter.get_config_path()).read_text())["mcpServers"][dep.name] == config


def test_runtime_references_are_never_resolved(tmp_path, monkeypatch):
    monkeypatch.setenv("EXAMPLE_SECRET", "must-not-be-written")
    adapter = OmpClientAdapter(project_root=tmp_path)
    remote = dependency(headers={"X-Token": "${EXAMPLE_SECRET}", "X-Literal": "literal-value"})
    stdio = dependency(
        transport="stdio",
        url=None,
        command="example",
        env={"TOKEN": "${EXAMPLE_SECRET}", "PLAIN": "literal-value"},
    )
    for dep in (remote, stdio):
        rendered = adapter.render_server_config(MCPIntegrator._build_self_defined_info(dep))
        assert "must-not-be-written" not in json.dumps(rendered)
        assert "${EXAMPLE_SECRET}" in json.dumps(rendered)
    assert (
        adapter.render_server_config(MCPIntegrator._build_self_defined_info(stdio))["env"]["PLAIN"]
        == "literal-value"
    )


@pytest.mark.parametrize(
    "value",
    [
        "!untrusted-command",
        "${UNSET}!untrusted-command",
        "${FIRST}${SECOND}!untrusted-command",
        "${UNSET:-!untrusted-command}",
        "${UNSET:-ordinary-default}",
        "GITHUB_TOKEN",
        "${UNSET}GITHUB_TOKEN",
    ],
)
@pytest.mark.parametrize("manifest", [False, True])
@pytest.mark.parametrize("field", ["headers", "env"])
def test_literal_bang_cannot_become_a_runtime_command(tmp_path, field, manifest, value):
    adapter = OmpClientAdapter(project_root=tmp_path)
    if field == "headers":
        info = {
            "name": "example",
            "remotes": [{"url": "https://example.test/mcp", "headers": {"X-Key": value}}],
        }
        dep = dependency(headers={"X-Key": value})
    else:
        info = {"name": "example", "_raw_stdio": {"command": "example", "env": {"KEY": value}}}
        dep = dependency(transport="stdio", url=None, command="example", env={"KEY": value})
    if manifest:
        info = MCPIntegrator._build_self_defined_info(dep)
    with pytest.raises(ValueError, match=r"omp (env|headers)"):
        adapter.render_server_config(info)
    assert not Path(adapter.get_config_path()).exists()
    assert not adapter.configure_mcp_server("example", server_info_cache={"example": info})
    assert not Path(adapter.get_config_path()).exists()


def test_registry_json_cannot_forge_helper_provenance(tmp_path):
    info = {
        "name": "example",
        "remotes": [{"url": "https://example.test/mcp"}],
        HEADER_HELPER_KEY: {"command": "steal-secrets", "keys": ["X-Key"]},
        "_extra": {"headersHelper": "steal-secrets", "headersHelperKeys": ["X-Key"]},
    }
    with pytest.raises(ValueError, match="manifest-declared"):
        OmpClientAdapter(project_root=tmp_path).render_server_config(info)
    dep = MCPDependency.from_dict({"name": "example"})
    overlaid = {dep.name: copy.deepcopy(info)}
    MCPIntegrator._apply_overlay(overlaid, dep)
    assert HEADER_HELPER_KEY not in overlaid[dep.name]


def test_helper_requires_declared_keys(tmp_path):
    info = MCPIntegrator._build_self_defined_info(dependency(extra={"headersHelper": "helper"}))
    with pytest.raises(ValueError, match="headersHelperKeys"):
        OmpClientAdapter(project_root=tmp_path).render_server_config(info)


@pytest.mark.parametrize(
    "runtime,helper_key", [("claude", "headersHelper"), ("codex", "http_headers_helper")]
)
def test_other_clients_keep_existing_helpers_without_key_metadata(tmp_path, runtime, helper_key):
    dep = dependency(extra={helper_key: "helper --json", "headersHelperKeys": ["X-Key"]})
    config = ClientFactory.create_client(runtime, project_root=tmp_path).render_server_config(
        MCPIntegrator._build_self_defined_info(dep)
    )
    assert config[helper_key] == "helper --json"
    assert "headersHelperKeys" not in config
    assert not any(str(value).startswith("!") for value in config.get("headers", {}).values())


def test_connection_comparison_ignores_only_native_controls(tmp_path):
    adapter = OmpClientAdapter(project_root=tmp_path)
    expected = {"type": "stdio", "command": "example"}
    assert adapter.matches_managed_server_config(
        {**expected, "instructions": False, "enabled": False}, expected
    )
    assert not adapter.matches_managed_server_config(
        {**expected, "command": "hand-edited"}, expected
    )
    assert not adapter.matches_managed_server_config(
        {**expected, "futureConnectionOption": True}, expected
    )


@pytest.mark.parametrize(
    "transport,native_type", [("http", "http"), ("streamable-http", "http"), ("sse", "sse")]
)
def test_remote_transport_discriminator(tmp_path, transport, native_type):
    dep = dependency(transport=transport)
    config = OmpClientAdapter(project_root=tmp_path).render_server_config(
        MCPIntegrator._build_self_defined_info(dep)
    )
    assert config["type"] == native_type
    assert config["url"] == dep.url


@pytest.mark.parametrize("selection", ["explicit_target", "config_target"])
def test_omp_target_detection_does_not_fall_back(tmp_path, selection):
    from apm_cli.core.target_detection import detect_target

    target, _reason = detect_target(project_root=tmp_path, **{selection: "omp"})
    assert target == "omp"


def test_url_environment_references_are_translated_without_resolution(tmp_path, monkeypatch):
    monkeypatch.setenv("MCP_HOST", "ambient.example.test")
    dep = dependency(url="https://${env:MCP_HOST}/mcp")
    adapter = OmpClientAdapter(project_root=tmp_path)
    config = adapter.render_server_config(MCPIntegrator._build_self_defined_info(dep))
    assert config["url"] == "https://${MCP_HOST}/mcp"


def test_runtime_oauth_and_auth_survive_unrelated_connection_update(tmp_path):
    adapter = OmpClientAdapter(project_root=tmp_path)
    expected = {"type": "http", "url": "https://example.test/mcp"}
    native = {
        **expected,
        "auth": {"type": "oauth", "credentialId": "fixture-account"},
        "oauth": {"clientId": "runtime-client"},
    }
    assert adapter.matches_managed_server_config(native, expected)
    assert adapter.update_config({"example": native})
    changed = {**expected, "url": "https://new.example.test/mcp"}
    assert adapter.update_config({"example": changed}, managed_fields=set(expected))
    actual = json.loads(Path(adapter.get_config_path()).read_text())["mcpServers"]["example"]
    assert actual == {**native, **changed}


def test_declared_oauth_remains_part_of_connection_ownership(tmp_path):
    adapter = OmpClientAdapter(project_root=tmp_path)
    expected = {
        "type": "http",
        "url": "https://example.test/mcp",
        "oauth": {"clientId": "declared-client"},
    }
    assert adapter.matches_managed_server_config(expected, expected)
    assert not adapter.matches_managed_server_config(
        {**expected, "oauth": {"clientId": "edited-client"}}, expected
    )
    assert adapter.update_config({"example": expected})
    removed = {key: value for key, value in expected.items() if key != "oauth"}
    assert adapter.update_config({"example": removed}, managed_fields=set(expected))
    actual = json.loads(Path(adapter.get_config_path()).read_text())["mcpServers"]["example"]
    assert actual == removed


def test_successful_write_records_declared_connection_hash(tmp_path):
    from apm_cli.install.mcp.ownership import mcp_native_hash

    adapter = OmpClientAdapter(project_root=tmp_path)
    dep = dependency(extra={"oauth": {"clientId": "declared-client"}})
    info = MCPIntegrator._build_self_defined_info(dep)
    assert adapter.configure_mcp_server(dep.name, server_info_cache={dep.name: info})
    expected = adapter.render_server_config(info)
    assert adapter.written_mcp_hashes == {dep.name: mcp_native_hash(expected)}
