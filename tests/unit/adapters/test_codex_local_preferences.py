"""Scoped Codex-native preferences retained for verified self-defined servers."""

from __future__ import annotations

from pathlib import Path

import pytest
import tomllib

from apm_cli.adapters.client.codex import CodexClientAdapter
from apm_cli.integration.mcp_integrator import MCPIntegrator
from apm_cli.models.dependency.mcp import MCPDependency


@pytest.fixture
def adapter(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    return CodexClientAdapter(project_root=tmp_path, user_scope=True)


def declaration(**overrides):
    raw = {
        "name": "local-server",
        "registry": False,
        "transport": "stdio",
        "command": "fixture-server",
        "args": ["--serve"],
        "env": {"DECLARED": "declared"},
        **overrides,
    }
    return MCPDependency.from_dict(raw)


def expected(adapter, dep):
    return adapter.render_server_config(MCPIntegrator._build_self_defined_info(dep))


def native_file(adapter) -> dict:
    return tomllib.loads(Path(adapter.get_config_path()).read_text())["mcp_servers"]


def test_local_tools_timeouts_and_undeclared_env_do_not_change_ownership(adapter):
    baseline = expected(adapter, declaration())
    native = {
        **baseline,
        "env": {**baseline["env"], "LOCAL_DEBUG": "1"},
        "startup_timeout_sec": 60,
        "tool_timeout_sec": 30,
        "tools": {"search": {"approval_mode": "approve"}},
    }
    assert adapter.matches_managed_server_config(native, baseline)
    assert adapter.managed_server_config(native, baseline=baseline) == baseline
    assert adapter.managed_server_config(native)["env"]["LOCAL_DEBUG"] == "1"


@pytest.mark.parametrize(
    "mutation",
    [
        {"command": "other-server"},
        {"args": ["--different"]},
        {"env": {"DECLARED": "changed"}},
        {"cwd": "/personal"},
        {"future_connection_field": True},
    ],
)
def test_connection_and_declared_env_changes_remain_conflicts(adapter, mutation):
    baseline = expected(adapter, declaration())
    native = {**baseline, "tools": {"search": {"approval_mode": "approve"}}, **mutation}
    assert not adapter.matches_managed_server_config(native, baseline)


def test_declared_local_field_is_managed_not_ignored(adapter):
    dep = declaration(startup_timeout_sec=10)
    baseline = expected(adapter, dep)
    assert baseline["startup_timeout_sec"] == 10
    assert not adapter.matches_managed_server_config(
        {**baseline, "startup_timeout_sec": 99}, baseline
    )


def test_absent_empty_args_and_env_match_declared_baseline(adapter):
    dep = declaration(args=[], env={})
    baseline = expected(adapter, dep)
    native = {"command": "fixture-server"}
    assert adapter.matches_managed_server_config(native, baseline)


def test_registry_style_projection_without_baseline_stays_strict(adapter):
    native = {"command": "fixture-server", "env": {"LOCAL_DEBUG": "1"}, "tools": {}}
    assert adapter.managed_server_config(native) == native


def test_update_preserves_local_preferences_and_managed_changes_are_written(adapter):
    old = declaration()
    old_config = expected(adapter, old)
    assert adapter.update_config(
        {
            old.name: {
                **old_config,
                "env": {**old_config["env"], "LOCAL_DEBUG": "1"},
                "startup_timeout_sec": 60,
                "tools": {"search": {"approval_mode": "approve"}},
            }
        }
    )
    new = declaration(args=["--changed"], env={"DECLARED": "changed"})
    new_config = expected(adapter, new)
    assert adapter.update_config(
        {new.name: new_config}, managed_fields=set(old_config), managed_env_keys={"DECLARED"}
    )
    actual = native_file(adapter)[new.name]
    assert actual == {
        **new_config,
        "env": {"DECLARED": "changed", "LOCAL_DEBUG": "1"},
        "startup_timeout_sec": 60,
        "tools": {"search": {"approval_mode": "approve"}},
    }
    # A repeated managed write is idempotent for retained local fields.
    assert adapter.update_config(
        {new.name: new_config}, managed_fields=set(new_config), managed_env_keys={"DECLARED"}
    )
    assert native_file(adapter)[new.name] == actual


def test_removed_declared_env_and_fields_are_not_retained_as_local(adapter):
    old = declaration(env={"DECLARED": "declared", "OLD_DECLARED": "old"}, startup_timeout_sec=10)
    old_config = expected(adapter, old)
    assert adapter.update_config({old.name: old_config})
    new = declaration()
    new_config = expected(adapter, new)
    assert adapter.update_config(
        {new.name: new_config},
        managed_fields=set(old_config),
        managed_env_keys={"DECLARED", "OLD_DECLARED"},
    )
    actual = native_file(adapter)[new.name]
    assert actual == new_config
    assert "startup_timeout_sec" not in actual
    assert "OLD_DECLARED" not in actual["env"]


def test_unmanaged_write_path_still_replaces_entry(adapter):
    old = declaration()
    config = expected(adapter, old)
    assert adapter.update_config(
        {old.name: {**config, "env": {**config["env"], "LOCAL_DEBUG": "1"}, "tools": {}}}
    )
    assert adapter.update_config({old.name: config})
    assert native_file(adapter)[old.name] == config


def test_self_defined_http_keeps_undeclared_environment_and_timeout(adapter):
    dep = declaration(
        transport="http", command=None, args=None, env=None, url="https://example.invalid/mcp"
    )
    baseline = expected(adapter, dep)
    native = {**baseline, "env": {"LOCAL_DEBUG": "1"}, "startup_timeout_sec": 60}
    assert adapter.matches_managed_server_config(native, baseline)
    assert adapter.update_config({dep.name: native})
    assert adapter.update_config(
        {dep.name: baseline}, managed_fields=set(baseline), managed_env_keys=set()
    )
    assert native_file(adapter)[dep.name] == native
