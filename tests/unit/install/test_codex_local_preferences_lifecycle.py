"""Self-defined Codex preferences survive reconciliation without weakening ownership."""

from pathlib import Path

import pytest
import tomlkit

from apm_cli.core.null_logger import NullCommandLogger
from apm_cli.core.safe_installer import SafeMCPInstaller
from apm_cli.core.scope import InstallScope
from apm_cli.factory import ClientFactory
from apm_cli.install.errors import MCPNativeConflictError
from apm_cli.install.mcp.ownership import (
    NativeMcpConnectionState,
    compare_native_mcp_connection,
    mcp_native_hash,
)
from apm_cli.integration.mcp_integrator import MCPIntegrator
from apm_cli.integration.mcp_integrator_install import _install_self_defined_deps
from apm_cli.models.dependency.mcp import MCPDependency


def dependency(**overrides):
    return MCPDependency.from_dict(
        {
            "name": "managed",
            "registry": False,
            "transport": "stdio",
            "command": "fixture-server",
            **overrides,
        }
    )


def install(dep, root, claims, *, stored=None, hashes=None):
    return _install_self_defined_deps(
        [dep],
        ["codex"],
        stored or {},
        set(),
        set(),
        root,
        False,
        False,
        None,
        NullCommandLogger(),
        claims,
        True,
        hashes,
    )


def seed(root, dep, **local):
    client = ClientFactory.create_client("codex", project_root=root)
    native = client.render_server_config(MCPIntegrator._build_self_defined_info(dep))
    native.update(local)
    path = Path(client.get_config_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '# Keep this project setting\nmodel = "local-model"\n'
        + tomlkit.dumps(
            {"mcp_servers": {dep.name: native, "personal": {"command": "personal-server"}}}
        ),
        encoding="utf-8",
    )
    return client, path


def entry(path):
    return tomlkit.parse(path.read_text(encoding="utf-8"))["mcp_servers"]["managed"]


def test_install_repeat_update_and_cleanup_preserve_local_preferences(tmp_path):
    old = dependency(env={"DECLARED": "old"})
    claims, hashes = {}, {}
    assert install(old, tmp_path, claims, hashes=hashes) == 1
    assert claims == {"codex": {old.name}}
    _, path = seed(
        tmp_path,
        old,
        tools=["read"],
        startup_timeout_sec=45,
        tool_timeout_sec=90,
        env={"DECLARED": "old", "LOCAL": "keep"},
    )
    before = path.read_bytes()
    stored = {old.name: old.to_dict()}
    assert install(old, tmp_path, claims, stored=stored, hashes=hashes) == 0
    assert path.read_bytes() == before

    new = dependency(command="new-server", args=["--new"], env={"DECLARED": "new"})
    assert install(new, tmp_path, claims, stored=stored, hashes=hashes) == 1
    assert dict(entry(path)) == {
        "command": "new-server",
        "args": ["--new"],
        "env": {"DECLARED": "new", "LOCAL": "keep"},
        "tools": ["read"],
        "startup_timeout_sec": 45,
        "tool_timeout_sec": 90,
    }
    assert hashes["codex"][old.name].startswith("sha256:")
    before = path.read_bytes()
    assert install(new, tmp_path, claims, stored={new.name: new.to_dict()}, hashes=hashes) == 0
    assert path.read_bytes() == before

    MCPIntegrator.remove_stale(
        {new.name},
        runtime="codex",
        project_root=tmp_path,
        scope=InstallScope.PROJECT,
        stored_configs={new.name: new.to_dict()},
        fail_on_write_error=True,
    )
    document = tomlkit.parse(path.read_text(encoding="utf-8"))
    assert document["mcp_servers"] == {"personal": {"command": "personal-server"}}
    assert document["model"] == "local-model"
    assert "# Keep this project setting" in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("remove", [False, True])
def test_declared_env_and_timeout_update_or_removal_reaches_writer(tmp_path, remove):
    old = dependency(env={"OWNED": "old"}, startup_timeout_sec=20)
    _, path = seed(tmp_path, old, env={"OWNED": "old", "LOCAL": "keep"}, tool_timeout_sec=60)
    new = dependency() if remove else dependency(env={"OWNED": "new"}, startup_timeout_sec=30)
    claims = {"codex": {old.name}}
    assert install(new, tmp_path, claims, stored={old.name: old.to_dict()}) == 1
    native = entry(path)
    assert native["tool_timeout_sec"] == 60
    if remove:
        assert "startup_timeout_sec" not in native
        assert native["env"] == {"LOCAL": "keep"}
    else:
        assert native["startup_timeout_sec"] == 30
        assert native["env"] == {"OWNED": "new", "LOCAL": "keep"}
    before = path.read_bytes()
    assert install(new, tmp_path, claims, stored={new.name: new.to_dict()}) == 0
    assert path.read_bytes() == before


@pytest.mark.parametrize("owned", [{"env": {"OWNED": "old"}}, {"startup_timeout_sec": 20}])
def test_each_owned_preference_removal_is_not_mistaken_for_local_customization(tmp_path, owned):
    old = dependency(**owned)
    client, path = seed(tmp_path, old)
    fields, env_keys = set(), set()
    assert (
        compare_native_mcp_connection(
            client,
            old.name,
            requested_info=MCPIntegrator._build_self_defined_info(dependency()),
            stored_config=old.to_dict(),
            managed=True,
            managed_fields=fields,
            managed_env_keys=env_keys,
        )
        is NativeMcpConnectionState.UPDATE_MANAGED
    )
    assert env_keys == ({"OWNED"} if "env" in owned else set())
    assert set(owned) <= fields
    assert (
        install(dependency(), tmp_path, {"codex": {old.name}}, stored={old.name: old.to_dict()})
        == 1
    )
    assert "startup_timeout_sec" not in entry(path)
    assert not entry(path).get("env")


@pytest.mark.parametrize(
    "local",
    [
        {"unknown_setting": True},
        {"command": "edited-command"},
        {"args": ["edited-arg"]},
        {"env": {"OWNED": "edited-value", "LOCAL": "keep"}},
        {"startup_timeout_sec": 99},
    ],
)
def test_native_connection_edits_conflict_without_rewriting_or_claiming(tmp_path, local):
    old = dependency(env={"OWNED": "old"}, startup_timeout_sec=20)
    _, path = seed(tmp_path, old, **local)
    before = path.read_bytes()
    claims = {"codex": {old.name}}
    with pytest.raises(MCPNativeConflictError):
        install(dependency(), tmp_path, claims, stored={old.name: old.to_dict()})
    assert path.read_bytes() == before
    assert not claims.get("codex")


@pytest.mark.parametrize("managed", [False, True])
def test_unverified_baseline_does_not_authorize_env_removal(tmp_path, managed):
    old = dependency(env={"OWNED": "old"})
    client, path = seed(tmp_path, old, env={"OWNED": "edited", "LOCAL": "keep"})
    before = path.read_bytes()
    fields, env_keys = set(), set()
    state = compare_native_mcp_connection(
        client,
        old.name,
        requested_info=MCPIntegrator._build_self_defined_info(dependency()),
        stored_config=old.to_dict(),
        managed=managed,
        managed_fields=fields,
        managed_env_keys=env_keys,
    )
    assert state is (
        NativeMcpConnectionState.CONFLICT if managed else NativeMcpConnectionState.MATCHING_FOREIGN
    )
    assert fields == env_keys == set()
    assert path.read_bytes() == before


def test_matching_foreign_codex_is_never_auto_adopted(tmp_path):
    dep = dependency()
    _, path = seed(tmp_path, dep, tools=["read"], env={"LOCAL": "keep"})
    before = path.read_bytes()
    claims, hashes = {}, {}
    assert install(dep, tmp_path, claims, hashes=hashes) == 0
    assert not claims.get("codex")
    assert not hashes.get("codex")
    assert path.read_bytes() == before


def test_registry_comparison_and_write_keep_full_native_semantics(tmp_path):
    dep = MCPDependency.from_dict({"name": "managed"})
    info = {
        "name": dep.name,
        "packages": [{"name": "fixture-package", "registry_name": "npm"}],
    }
    installer = SafeMCPInstaller("codex", project_root=tmp_path)
    summary = installer.install_servers([dep.name], server_info_cache={dep.name: info})
    assert summary.installed == [dep.name]
    path = Path(installer.adapter.get_config_path())
    native = entry(path)
    assert summary.native_hashes[dep.name] == mcp_native_hash(dict(native))
    document = tomlkit.parse(path.read_text(encoding="utf-8"))
    document["mcp_servers"][dep.name]["tool_timeout_sec"] = 60
    document["mcp_servers"][dep.name]["env"] = {"LOCAL": "keep"}
    path.write_text(tomlkit.dumps(document), encoding="utf-8")
    before = path.read_bytes()
    env_keys = set()
    assert (
        compare_native_mcp_connection(
            installer.adapter,
            dep.name,
            requested_info=info,
            stored_config=dep.to_dict(),
            managed=True,
            native_hash=summary.native_hashes[dep.name],
            registry_request=True,
            managed_env_keys=env_keys,
        )
        is NativeMcpConnectionState.CONFLICT
    )
    assert env_keys == set()
    assert path.read_bytes() == before
    # A registry replacement uses the original strict writer, not preference merging.
    summary = installer.install_servers(
        [dep.name], server_info_cache={dep.name: info}, replace_existing=True
    )
    assert summary.installed == [dep.name]
    assert dict(entry(path)) == installer.adapter.render_server_config(info)
    assert summary.native_hashes[dep.name] == mcp_native_hash(dict(entry(path)))
