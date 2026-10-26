"""Per-declaration MCP routing and native omp ownership regression coverage."""

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from apm_cli.core.null_logger import NullCommandLogger
from apm_cli.core.scope import InstallScope
from apm_cli.deps.lockfile import LockFile
from apm_cli.factory import ClientFactory
from apm_cli.install.errors import (
    FrozenInstallError,
    MCPNativeConflictError,
    RequiredIntegrationError,
)
from apm_cli.install.service import InstallService
from apm_cli.integration.mcp_config_view import CurrentMcpConfigView
from apm_cli.integration.mcp_integrator import MCPIntegrator
from apm_cli.integration.mcp_integrator_install import _install_self_defined_deps, run_mcp_install
from apm_cli.models.dependency.mcp import MCPDependency


def dependency(targets=None):
    raw = {
        "name": "managed",
        "registry": False,
        "transport": "stdio",
        "command": "fixture-server",
    }
    if targets is not None:
        raw["targets"] = targets
    return MCPDependency.from_dict(raw)


def install_self(dep, root, ownership, hashes=None, stored=None, targets=None):
    return _install_self_defined_deps(
        [dep],
        targets or ["omp"],
        stored or {},
        set(),
        set(),
        root,
        False,
        False,
        None,
        NullCommandLogger(),
        ownership,
        True,
        hashes,
    )


def native_config(root, dep, **local):
    client = ClientFactory.create_client("omp", project_root=root, user_scope=False)
    native = client.render_server_config(MCPIntegrator._build_self_defined_info(dep))
    native.update(local)
    path = Path(client.get_config_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        client.mcp_servers_key: {dep.name: native, "personal": {"command": "personal"}},
        "disabledServers": ["managed", "personal"],
        "settings": {"keep": True},
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path, payload


@pytest.mark.parametrize(
    "targets, expected", [(None, {"omp", "claude"}), (["omp"], {"omp"}), ([], set())]
)
def test_self_defined_routes_each_declaration(tmp_path, targets, expected):
    dep = dependency(targets)
    calls = []

    def install(runtime, names, *args, **kwargs):
        calls.append(runtime)
        kwargs["installed_servers"].update(names)
        return True

    with patch.object(MCPIntegrator, "_install_for_runtime", side_effect=install):
        ownership = {}
        install_self(dep, tmp_path, ownership, targets=["omp", "claude"])
    assert set(calls) == expected
    assert {runtime for runtime, names in ownership.items() if names} == expected


def test_empty_targets_clears_claims_without_resolving_or_writing(tmp_path):
    dep = dependency([])
    ownership = {"omp": {dep.name}}
    with (
        patch(
            "apm_cli.integration.mcp_integrator_install._resolve_target_runtimes",
            return_value=["omp"],
        ),
        patch("apm_cli.integration.mcp_integrator_install._validate_target_configs") as validate,
        patch("apm_cli.integration.mcp_integrator_install._install_self_defined_deps") as install,
    ):
        assert run_mcp_install([dep], project_root=tmp_path, managed_target_servers=ownership) == 0
    assert ownership == {}
    validate.assert_not_called()
    install.assert_not_called()


def test_equivalent_foreign_omp_is_adopted_without_rewriting(tmp_path):
    dep = dependency(["omp"])
    path, _ = native_config(tmp_path, dep, enabled=False, instructions="local preference")
    before = path.read_bytes()
    ownership, hashes = {}, {}
    assert install_self(dep, tmp_path, ownership, hashes) == 0
    assert ownership == {"omp": {"managed"}}
    assert hashes["omp"]["managed"].startswith("sha256:")
    assert path.read_bytes() == before


def test_differing_foreign_omp_is_not_claimed(tmp_path):
    dep = dependency(["omp"])
    path, _ = native_config(tmp_path, dep, command="personal-server")
    before = path.read_bytes()
    ownership = {}
    with pytest.raises(MCPNativeConflictError):
        install_self(dep, tmp_path, ownership)
    assert not ownership.get("omp")
    assert path.read_bytes() == before


def test_omp_cleanup_preserves_control_arrays_and_unrelated_entries(tmp_path):
    dep = dependency(["omp"])
    path, payload = native_config(tmp_path, dep, enabled=False, instructions="keep locally")
    MCPIntegrator.remove_stale(
        {dep.name},
        runtime="omp",
        project_root=tmp_path,
        scope=InstallScope.PROJECT,
        stored_configs={dep.name: dep.to_dict()},
        fail_on_write_error=True,
    )
    del payload["mcpServers"][dep.name]
    assert json.loads(path.read_text()) == payload


def test_omp_cleanup_refuses_edited_connection(tmp_path):
    dep = dependency(["omp"])
    path, _ = native_config(tmp_path, dep, command="personal-server")
    before = path.read_bytes()
    with pytest.raises(RequiredIntegrationError):
        MCPIntegrator.remove_stale(
            {dep.name},
            runtime="omp",
            project_root=tmp_path,
            scope=InstallScope.PROJECT,
            stored_configs={dep.name: dep.to_dict()},
            fail_on_write_error=True,
        )
    assert path.read_bytes() == before


def test_frozen_requires_only_declared_target_claims():
    dep = dependency(["omp"])
    configs = {dep.name: dep.to_dict()}
    view = CurrentMcpConfigView((dep,), configs, {}, ())
    lock = LockFile()
    lock.mcp_configs = configs
    lock.mcp_target_servers = {"omp": [dep.name]}
    InstallService.enforce_frozen_services(
        lock,
        mcp_servers={dep.name},
        mcp_targets=["omp", "claude"],
        lsp_servers=set(),
        lsp_targets=[],
        current_mcp=view,
        user_scope=False,
    )
    lock.mcp_target_servers["claude"] = [dep.name]
    with pytest.raises(FrozenInstallError, match="cannot replay"):
        InstallService.enforce_frozen_services(
            lock,
            mcp_servers={dep.name},
            mcp_targets=["omp", "claude"],
            lsp_servers=set(),
            lsp_targets=[],
            current_mcp=view,
            user_scope=False,
        )


def test_registry_install_skips_disallowed_runtime(tmp_path):
    from apm_cli.integration.mcp_integrator_install import _install_registry_group

    dep = MCPDependency.from_dict({"name": "registry-server", "targets": ["omp"]})
    operations = Mock()
    operations.registry_client.source = "default"
    operations.registry_client.registry_url = "https://example.invalid/registry"
    operations.check_servers_needing_installation.return_value = [dep.name]
    operations.collect_environment_variables.return_value = {}
    operations.collect_runtime_variables.return_value = {}
    info = {"name": dep.name, "packages": []}
    installed = []

    def install(runtime, names, *args, **kwargs):
        installed.append(runtime)
        kwargs["installed_servers"].update(names)
        return True

    with patch.object(MCPIntegrator, "_install_for_runtime", side_effect=install):
        ownership = {}
        _install_registry_group(
            operations,
            [dep.name],
            {dep.name: dep},
            [dep],
            ["omp", "claude"],
            {},
            set(),
            set(),
            tmp_path,
            False,
            False,
            None,
            NullCommandLogger(),
            ownership,
            prevalidated_servers={dep.name: info},
        )
    assert installed == ["omp"]
    assert ownership == {"omp": {dep.name}}


@pytest.mark.parametrize("new_targets", [[], ["claude"]])
def test_bundle_target_change_retires_exact_old_omp_entry(tmp_path, new_targets):
    from apm_cli.core.deployment_ledger import DeploymentLedgerCodec
    from apm_cli.install.mcp.integration import run_owned_mcp_integration

    old = dependency(["omp"])
    path, payload = native_config(tmp_path, old)
    lock = LockFile()
    lock.mcp_servers = [old.name]
    lock.mcp_configs = {old.name: old.to_dict()}
    lock.mcp_config_provenance = {old.name: "bundle:fixture"}
    DeploymentLedgerCodec.replace_mcp_target_servers(lock, {"omp": [old.name]})
    lock_path = tmp_path / "apm.lock.yaml"
    lock.write(lock_path)
    new = dependency(new_targets)

    def install(deps, **kwargs):
        claims = kwargs["managed_target_servers"]
        claims.clear()
        for target in new_targets:
            claims[target] = {old.name}
        return len(new_targets)

    with patch.object(MCPIntegrator, "install", side_effect=install):
        run_owned_mcp_integration(
            dependencies=[new],
            owner="fixture",
            lock_path=lock_path,
            project_root=tmp_path,
            user_scope=False,
            target_runtimes=["omp", "claude"],
        )
    del payload["mcpServers"][old.name]
    assert json.loads(path.read_text()) == payload
    updated = LockFile.read(lock_path)
    assert not updated.mcp_target_servers.get("omp")
    assert updated.mcp_configs[old.name]["targets"] == new_targets


def test_audit_rejects_excluded_target_ownership(tmp_path):
    from apm_cli.policy.ci_checks import _check_config_consistency

    dep = dependency(["omp"])
    configs = {dep.name: dep.to_dict()}
    view = CurrentMcpConfigView((dep,), configs, {}, ())
    lock = LockFile()
    lock.mcp_configs = configs
    lock.mcp_target_servers = {"claude": [dep.name]}
    manifest = Mock(package_path=tmp_path)
    with patch.object(CurrentMcpConfigView, "derive", return_value=view):
        result = _check_config_consistency(manifest, lock)
    assert not result.passed
    assert any("excluded target claude" in detail for detail in result.details)


def test_adoption_ignores_runtime_auth_and_undeclared_oauth(tmp_path):
    from apm_cli.install.mcp.ownership import mcp_native_hash

    dep = dependency(["omp"])
    path, _ = native_config(
        tmp_path, dep, auth={"token": "runtime-secret"}, oauth={"clientId": "runtime-client"}
    )
    before = path.read_bytes()
    claims, hashes = {}, {}
    install_self(dep, tmp_path, claims, hashes)
    client = ClientFactory.create_client("omp", project_root=tmp_path)
    rendered = client.render_server_config(MCPIntegrator._build_self_defined_info(dep))
    assert hashes["omp"][dep.name] == mcp_native_hash(rendered)
    assert claims == {"omp": {dep.name}}
    assert path.read_bytes() == before


@pytest.mark.parametrize("declared_oauth", [False, True])
@pytest.mark.parametrize("metadata_field", ["oauth", "auth"])
def test_registry_written_hash_distinguishes_declared_and_runtime_oauth(
    tmp_path, declared_oauth, metadata_field
):
    from apm_cli.core.safe_installer import SafeMCPInstaller
    from apm_cli.install.mcp.ownership import (
        NativeMcpConnectionState,
        compare_native_mcp_connection,
        require_removable_mcp_connections,
    )

    raw = {"name": "managed", "targets": ["omp"]}
    if declared_oauth:
        raw[metadata_field] = {"clientId": "declared-client"}
    dep = MCPDependency.from_dict(raw)
    source = MCPDependency.from_dict(
        {
            "name": dep.name,
            "registry": False,
            "transport": "http",
            "url": "https://example.invalid/mcp",
        }
    )
    info = MCPIntegrator._build_self_defined_info(source)
    cache = {dep.name: info}
    MCPIntegrator._apply_overlay(cache, dep)
    installer = SafeMCPInstaller("omp", project_root=tmp_path)
    summary = installer.install_servers([dep.name], server_info_cache=cache)
    assert summary.installed == [dep.name]
    native_hash = summary.native_hashes[dep.name]
    path = Path(installer.adapter.get_config_path())
    document = json.loads(path.read_text())
    native = document["mcpServers"][dep.name]
    other_field = "auth" if metadata_field == "oauth" else "oauth"
    native[other_field] = {"clientId": "runtime-client"}
    if not declared_oauth:
        native[metadata_field] = {"clientId": "runtime-client"}
    path.write_text(json.dumps(document), encoding="utf-8")
    fields = set()
    assert (
        compare_native_mcp_connection(
            installer.adapter,
            dep.name,
            requested_info=info,
            stored_config=dep.to_dict(),
            managed=True,
            native_hash=native_hash,
            registry_request=True,
            managed_fields=fields,
        )
        is NativeMcpConnectionState.MATCHING_MANAGED
    )
    assert (metadata_field in fields) is declared_oauth
    assert require_removable_mcp_connections(
        installer.adapter, {dep.name}, {dep.name: dep.to_dict()}, {dep.name: native_hash}
    ) == {dep.name}
    native[metadata_field] = {"clientId": "edited-client"}
    path.write_text(json.dumps(document), encoding="utf-8")
    if declared_oauth:
        with pytest.raises(RequiredIntegrationError):
            require_removable_mcp_connections(
                installer.adapter, {dep.name}, {dep.name: dep.to_dict()}, {dep.name: native_hash}
            )
    else:
        assert require_removable_mcp_connections(
            installer.adapter, {dep.name}, {dep.name: dep.to_dict()}, {dep.name: native_hash}
        ) == {dep.name}


@pytest.mark.parametrize("remove_oauth", [False, True])
def test_explicit_oauth_update_or_removal_reaches_native_writer(tmp_path, remove_oauth):
    old = MCPDependency.from_dict(
        {
            "name": "managed",
            "registry": False,
            "transport": "http",
            "url": "https://example.invalid/mcp",
            "targets": ["omp"],
            "oauth": {"clientId": "old-client"},
        }
    )
    path, _ = native_config(tmp_path, old, auth={"token": "runtime-secret"})
    raw = old.to_dict()
    if remove_oauth:
        raw.pop("oauth")
    else:
        raw["oauth"] = {"clientId": "new-client"}
    new = MCPDependency.from_dict(raw)
    claims, hashes = {"omp": {old.name}}, {}
    assert install_self(new, tmp_path, claims, hashes, stored={old.name: old.to_dict()}) == 1
    native = json.loads(path.read_text())["mcpServers"][old.name]
    if remove_oauth:
        assert "oauth" not in native
    else:
        assert native["oauth"] == {"clientId": "new-client"}
    assert native["auth"] == {"token": "runtime-secret"}
    assert hashes["omp"][old.name].startswith("sha256:")


def test_user_edited_declared_oauth_blocks_managed_update(tmp_path):
    old = MCPDependency.from_dict(
        {
            "name": "managed",
            "registry": False,
            "command": "fixture-server",
            "transport": "stdio",
            "targets": ["omp"],
            "oauth": {"clientId": "declared-client"},
        }
    )
    path, _ = native_config(tmp_path, old, oauth={"clientId": "personal-client"})
    before = path.read_bytes()
    new = dependency(["omp"])
    with pytest.raises(MCPNativeConflictError):
        install_self(new, tmp_path, {"omp": {old.name}}, stored={old.name: old.to_dict()})
    assert path.read_bytes() == before


@pytest.mark.parametrize("remove_auth", [False, True])
def test_explicit_auth_update_or_removal_reaches_native_writer(tmp_path, remove_auth):
    old = MCPDependency.from_dict(
        {
            "name": "managed",
            "registry": False,
            "transport": "http",
            "url": "https://example.invalid/mcp",
            "targets": ["omp"],
            "auth": {"type": "oauth", "credentialId": "declared-account"},
        }
    )
    path, _ = native_config(tmp_path, old, oauth={"clientId": "runtime-client"})
    raw = old.to_dict()
    if remove_auth:
        raw.pop("auth")
    else:
        raw["auth"] = {"type": "oauth", "credentialId": "new-account"}
    new = MCPDependency.from_dict(raw)
    claims, hashes = {"omp": {old.name}}, {}
    assert install_self(new, tmp_path, claims, hashes, stored={old.name: old.to_dict()}) == 1
    native = json.loads(path.read_text())["mcpServers"][old.name]
    if remove_auth:
        assert "auth" not in native
    else:
        assert native["auth"] == raw["auth"]
    assert native["oauth"] == {"clientId": "runtime-client"}
    assert hashes["omp"][old.name].startswith("sha256:")


def test_user_edited_declared_auth_blocks_managed_removal(tmp_path):
    old = MCPDependency.from_dict(
        {
            "name": "managed",
            "registry": False,
            "transport": "stdio",
            "command": "fixture-server",
            "targets": ["omp"],
            "auth": {"type": "oauth", "credentialId": "declared-account"},
        }
    )
    path, _ = native_config(
        tmp_path, old, auth={"type": "oauth", "credentialId": "personal-account"}
    )
    before = path.read_bytes()
    with pytest.raises(MCPNativeConflictError):
        install_self(
            dependency(["omp"]), tmp_path, {"omp": {old.name}}, stored={old.name: old.to_dict()}
        )
    assert path.read_bytes() == before
