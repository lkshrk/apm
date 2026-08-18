"""Native Agent Plugin MCP preparation contracts."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse

from apm_cli.agent_plugins.ir import (
    AgentPlugin,
    AgentPluginComponents,
    AgentPluginIdentity,
    AgentPluginMcpServer,
    McpServerType,
    SourceProvenance,
)
from apm_cli.agent_plugins.projection import project_agent_plugin_package
from apm_cli.install.mcp.integration import prepare_attached_agent_plugin_mcp
from apm_cli.models.apm_package import APMPackage, PackageInfo
from apm_cli.models.dependency.mcp import MCPDependency
from apm_cli.models.dependency.native_mcp import (
    AgentPluginMCPPreparation,
    AgentPluginMCPPreparationFailure,
    AgentPluginMCPPreparationSuccess,
)


def _server(
    root: Path,
    name: str,
    server_type: McpServerType,
    **overrides,
) -> AgentPluginMcpServer:
    values = {
        "name": name,
        "server_type": server_type,
        "command": None,
        "args": (),
        "env": (),
        "cwd": None,
        "url": None,
        "headers": (),
        "provenance": SourceProvenance(
            path=root / "mcp.json",
            json_pointer=f"/mcpServers/{name}",
        ),
    }
    values.update(overrides)
    return AgentPluginMcpServer(**values)


def _plugin(root: Path) -> AgentPlugin:
    servers = (
        _server(
            root,
            "stdio-root",
            McpServerType.STDIO,
            command="./bin/server",
            args=(
                "${PLUGIN_ROOT}/bin",
                "${PLUGIN_DATA}/cache",
                "${UNKNOWN}/literal",
                "${PLUGIN_ROOT}/${UNKNOWN}/${PLUGIN_DATA}",
                "${GITHUB_TOKEN}",
            ),
            env=(
                ("ROOT_PATH", "${PLUGIN_ROOT}/env"),
                ("DATA_PATH", "${PLUGIN_DATA}/env"),
                ("UNKNOWN_PATH", "${UNKNOWN}/env"),
                ("AMBIENT_LITERAL", "${GITHUB_TOKEN}"),
            ),
            cwd="${PLUGIN_ROOT}/work",
        ),
        _server(
            root,
            "stdio-data",
            McpServerType.STDIO,
            command="server",
            cwd="${PLUGIN_DATA}/work",
        ),
        _server(
            root,
            "same-origin",
            McpServerType.STREAMABLE_HTTP,
            url="https://github.com/example/mcp?literal=${PLUGIN_ROOT}",
            headers=(
                ("X-Literal", "${GITHUB_TOKEN}"),
                ("X-Plugin-Root", "${PLUGIN_ROOT}"),
            ),
        ),
        _server(
            root,
            "cross-origin",
            McpServerType.SSE,
            url="https://mcp.example.test/events",
            headers=(
                ("Authorization", "Bearer declared-literal"),
                ("X-Plugin-Data", "${PLUGIN_DATA}"),
            ),
        ),
    )
    return AgentPlugin(
        specification_version="1",
        root=root,
        manifest=SourceProvenance(path=root / "plugin.json", json_pointer=""),
        identity=AgentPluginIdentity(
            name="native-plugin",
            version="2.4.1",
            description=None,
            author=(),
            homepage=None,
            repository=None,
            license=None,
            keywords=(),
        ),
        components=AgentPluginComponents(skills=(), mcp_servers=servers),
        apm_extension=None,
        apm_configuration=None,
        diagnostics=(),
    )


def _package_info(plugin: AgentPlugin, root: Path) -> PackageInfo:
    return PackageInfo(
        package=APMPackage(
            name="compatibility-shell",
            version="0.0.0",
            source="ignored/source",
            agent_plugin=plugin,
        ),
        install_path=root,
    )


def _prepared_by_name(preparation: AgentPluginMCPPreparation) -> dict:
    return {result.server_name: result.config for result in preparation.successes}


def test_native_preparation_expands_only_portable_path_placeholders(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path / "source")
    plugin_root = tmp_path / "deployed" / "plugin"
    plugin_data = tmp_path / "state" / "plugin-data"

    prepared = prepare_attached_agent_plugin_mcp(
        _package_info(plugin, tmp_path),
        plugin_root=plugin_root,
        plugin_data=plugin_data,
    )

    configs = _prepared_by_name(prepared)
    stdio_root = configs["stdio-root"]
    assert stdio_root.command == "./bin/server"
    assert stdio_root.args == (
        f"{plugin_root}/bin",
        f"{plugin_data}/cache",
        "${UNKNOWN}/literal",
        f"{plugin_root}/${{UNKNOWN}}/{plugin_data}",
        "${GITHUB_TOKEN}",
    )
    assert stdio_root.env == (
        ("ROOT_PATH", f"{plugin_root}/env"),
        ("DATA_PATH", f"{plugin_data}/env"),
        ("UNKNOWN_PATH", "${UNKNOWN}/env"),
        ("AMBIENT_LITERAL", "${GITHUB_TOKEN}"),
    )
    assert stdio_root.cwd == f"{plugin_root}/work"
    assert configs["stdio-data"].cwd == f"{plugin_data}/work"


def test_remote_urls_and_headers_remain_literal_across_origins(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path / "source")

    prepared = prepare_attached_agent_plugin_mcp(
        _package_info(plugin, tmp_path),
        plugin_root=tmp_path / "deployed",
        plugin_data=tmp_path / "data",
    )

    configs = _prepared_by_name(prepared)
    same_origin = urlparse(configs["same-origin"].url)
    assert same_origin.scheme == "https"
    assert same_origin.hostname == "github.com"
    assert same_origin.path == "/example/mcp"
    assert same_origin.query == "literal=${PLUGIN_ROOT}"
    assert configs["same-origin"].url == plugin.components.mcp_servers[2].url
    assert configs["same-origin"].headers == (
        ("X-Literal", "${GITHUB_TOKEN}"),
        ("X-Plugin-Root", "${PLUGIN_ROOT}"),
    )
    cross_origin = urlparse(configs["cross-origin"].url)
    assert cross_origin.scheme == "https"
    assert cross_origin.hostname == "mcp.example.test"
    assert cross_origin.path == "/events"
    assert cross_origin.query == ""
    assert configs["cross-origin"].url == plugin.components.mcp_servers[3].url
    assert configs["cross-origin"].headers == (
        ("Authorization", "Bearer declared-literal"),
        ("X-Plugin-Data", "${PLUGIN_DATA}"),
    )


def test_native_preparation_never_inherits_ambient_credentials(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ambient = {
        "GITHUB_TOKEN": "ambient-github",
        "GITHUB_APM_PAT": "ambient-apm",
        "ADO_APM_PAT": "ambient-ado",
        "GH_TOKEN": "ambient-gh",
    }
    for name, value in ambient.items():
        monkeypatch.setenv(name, value)
    plugin = _plugin(tmp_path / "source")

    prepared = prepare_attached_agent_plugin_mcp(
        _package_info(plugin, tmp_path),
        plugin_root=tmp_path / "deployed",
        plugin_data=tmp_path / "data",
    )

    configs = _prepared_by_name(prepared)
    stdio_env = dict(configs["stdio-root"].env)
    assert set(stdio_env) == {
        "ROOT_PATH",
        "DATA_PATH",
        "UNKNOWN_PATH",
        "AMBIENT_LITERAL",
    }
    assert stdio_env["AMBIENT_LITERAL"] == "${GITHUB_TOKEN}"
    assert configs["stdio-root"].args[-1] == "${GITHUB_TOKEN}"
    assert configs["same-origin"].headers == plugin.components.mcp_servers[2].headers
    assert configs["cross-origin"].headers == plugin.components.mcp_servers[3].headers
    assert all(value not in repr(prepared) for value in ambient.values())


def test_preparation_preserves_plugin_and_per_server_provenance(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path / "source")

    prepared = prepare_attached_agent_plugin_mcp(
        _package_info(plugin, tmp_path),
        plugin_root=tmp_path / "deployed",
        plugin_data=tmp_path / "data",
    )

    assert prepared.provenance.specification_version == plugin.specification_version
    assert prepared.provenance.plugin_name == plugin.identity.name
    assert prepared.provenance.plugin_version == plugin.identity.version
    assert prepared.provenance.source_root == plugin.root
    assert prepared.provenance.manifest is plugin.manifest
    for result, server in zip(prepared.successes, plugin.components.mcp_servers, strict=True):
        assert result.provenance.plugin is prepared.provenance
        assert result.provenance.declaration is server.provenance


def test_attached_ir_is_the_only_ingress_fact_source(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path / "source")
    projected = PackageInfo(
        package=project_agent_plugin_package(plugin),
        install_path=tmp_path / "projected",
    )
    compatibility_variant = _package_info(plugin, tmp_path / "variant")
    compatibility_variant.package.name = "different-shell"
    compatibility_variant.package.version = "99.0.0"
    compatibility_variant.package.source = "different/source"

    projected_result = prepare_attached_agent_plugin_mcp(
        projected,
        plugin_root=tmp_path / "deployed",
        plugin_data=tmp_path / "data",
    )
    variant_result = prepare_attached_agent_plugin_mcp(
        compatibility_variant,
        plugin_root=tmp_path / "deployed",
        plugin_data=tmp_path / "data",
    )

    assert projected_result == variant_result


def test_preparation_is_read_only_and_returns_typed_per_server_results(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path / "source")
    sentinels = (
        tmp_path / ".vscode" / "mcp.json",
        tmp_path / "apm.lock.yaml",
        tmp_path / ".apm" / "deployment-ledger.json",
    )
    for sentinel in sentinels:
        sentinel.parent.mkdir(parents=True, exist_ok=True)
        sentinel.write_bytes(b"sentinel")

    with (
        patch("pathlib.Path.write_text") as write_text,
        patch("pathlib.Path.write_bytes") as write_bytes,
        patch("pathlib.Path.open") as path_open,
        patch("apm_cli.integration.mcp_integrator.MCPIntegrator.install") as legacy_install,
        patch("apm_cli.integration.mcp_integrator.MCPIntegrator.update_lockfile") as lock_write,
        patch(
            "apm_cli.core.deployment_ledger.DeploymentLedgerCodec.replace_mcp_target_servers"
        ) as ledger_write,
    ):
        prepared = prepare_attached_agent_plugin_mcp(
            _package_info(plugin, tmp_path),
            plugin_root=tmp_path / "deployed",
            plugin_data=tmp_path / "data",
        )

    write_text.assert_not_called()
    write_bytes.assert_not_called()
    path_open.assert_not_called()
    legacy_install.assert_not_called()
    lock_write.assert_not_called()
    ledger_write.assert_not_called()
    assert all(sentinel.read_bytes() == b"sentinel" for sentinel in sentinels)
    assert all(isinstance(result, AgentPluginMCPPreparationSuccess) for result in prepared.results)
    assert prepared.failures == ()

    first = prepared.successes[0]
    failure = AgentPluginMCPPreparationFailure(
        server_name=first.server_name,
        provenance=first.provenance,
        code="target.prepare.failed",
        message="target adapter rejected the prepared server",
    )
    partial = replace(prepared, results=(first, failure))
    assert partial.successes == (first,)
    assert partial.failures == (failure,)


def test_legacy_nonportable_auth_extension_remains_separate(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path / "source")
    native = prepare_attached_agent_plugin_mcp(
        _package_info(plugin, tmp_path),
        plugin_root=tmp_path / "deployed",
        plugin_data=tmp_path / "data",
    )
    legacy = MCPDependency.from_dict(
        {
            "name": "legacy-oauth",
            "transport": "http",
            "registry": False,
            "url": "https://legacy.example.test/mcp",
            "extra": {"oauth": {"clientId": "explicit-client"}},
        }
    )

    assert legacy.extra == {"oauth": {"clientId": "explicit-client"}}
    assert not hasattr(native.successes[0].config, "extra")
