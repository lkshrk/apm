"""Component-granular executable trust contracts for Agent Plugins."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from apm_cli.agent_plugins.ir import (
    AgentPlugin,
    AgentPluginAsset,
    AgentPluginComponents,
    AgentPluginExecutable,
    AgentPluginIdentity,
    AgentPluginMcpServer,
    AgentPluginSkill,
    ApmExtensionComponents,
    ApmExtensionFileComponent,
    ApmExtensionHookComponent,
    ApmExtensionLspComponent,
    ApmExtensionLspServer,
    FrozenJsonObject,
    McpServerType,
    SourceProvenance,
)
from apm_cli.install.exec_gate import evaluate_agent_plugin_executable_trust
from apm_cli.security.executables import (
    ASSET_STATE_EXTERNAL,
    ASSET_STATE_MISSING,
    ASSET_STATE_VERIFIED,
    COMPONENT_KIND_APM_EXTENSION,
    COMPONENT_KIND_APM_HOOK,
    COMPONENT_KIND_APM_LSP,
    COMPONENT_KIND_MCP_REMOTE,
    COMPONENT_KIND_MCP_STDIO,
    COMPONENT_KIND_SKILL_ASSET,
    EXEC_CLASS_DECLARATIVE,
    EXEC_CLASS_EXECUTABLE,
    EXEC_CLASS_UNKNOWN,
    EXEC_TYPE_BIN,
    EXEC_TYPE_CANVAS,
    EXEC_TYPE_HOOKS,
    EXEC_TYPE_LSP,
    EXEC_TYPE_MCP,
    FAILURE_APPROVAL_REQUIRED,
    FAILURE_INVALID_COMPONENT,
    FAILURE_INVALID_PROVENANCE,
    FAILURE_MISSING_ASSET,
    FAILURE_POLICY_DENIED,
    LAYER_EXPLICIT_CONSENT,
    LAYER_INVALID_COMPONENT,
    LAYER_ORG_DENY,
    LAYER_PROJECT_ALLOW,
    LAYER_USER_ALLOW,
    TRUST_DECLARATIVE,
    TRUST_DENIED,
    ExecSourceFacts,
    ExecTrustContext,
    ExecutableComponent,
    assemble_agent_plugin_exec_trust_context,
    inventory_agent_plugin_executables,
    resolve_agent_plugin_exec_decision,
)

PLUGIN_KEY = "portable-plugin#1.2.3"
ASSET_DIGEST = "a" * 64
SOURCE_FACTS = ExecSourceFacts(
    canonical_source="https://example.invalid/plugins/portable-plugin",
    resolved_revision="8a0f4d2",
    content_digest="sha256:0123456789abcdef",
    integrity_verified=True,
)


def _policy(**updates: object) -> ExecTrustContext:
    values: dict[str, object] = {
        "gate_enabled": True,
        "org_deny_all": False,
        "org_deny": frozenset(),
        "org_require": frozenset(),
        "org_recommend": frozenset(),
        "org_enforce": frozenset(),
        "org_bin_deny_all": False,
        "org_bin_deny": frozenset(),
        "project_allow": {},
        "project_deny": {},
        "user_allow": {},
        "user_deny": {},
    }
    values.update(updates)
    return ExecTrustContext(**values)


def _plugin(root: Path, *, version: str | None = "1.2.3") -> AgentPlugin:
    manifest = SourceProvenance(root / "plugin.json", "")
    skill_manifest = SourceProvenance(root / "skills" / "review" / "SKILL.md", "")
    skill = AgentPluginSkill(
        directory_name="review",
        name="review",
        description="Review a change",
        root=root / "skills" / "review",
        manifest=skill_manifest,
        assets=(
            AgentPluginAsset(
                path="skills/review/SKILL.md",
                source=skill_manifest,
                sha256=ASSET_DIGEST,
                size=42,
                executable_mode=0,
            ),
        ),
    )
    server_asset = AgentPluginAsset(
        path="bin/server",
        source=SourceProvenance(root / "bin" / "server", ""),
        sha256=ASSET_DIGEST,
        size=64,
        executable_mode=0o111,
    )
    stdio_provenance = SourceProvenance(
        root / "mcp.json",
        "/mcpServers/local-tools",
    )
    stdio = AgentPluginMcpServer(
        name="local-tools",
        server_type=McpServerType.STDIO,
        command="./bin/server",
        args=("--mode", "safe"),
        env=(),
        cwd="${PLUGIN_ROOT}",
        url=None,
        headers=(),
        provenance=stdio_provenance,
        executables=(
            AgentPluginExecutable(
                declaration="./bin/server",
                plugin_relative_path="bin/server",
                asset=server_asset,
                provenance=SourceProvenance(
                    root / "mcp.json",
                    "/mcpServers/local-tools/command",
                ),
            ),
        ),
    )
    remote = AgentPluginMcpServer(
        name="remote-tools",
        server_type=McpServerType.STREAMABLE_HTTP,
        command=None,
        args=(),
        env=(),
        cwd=None,
        url="https://example.invalid/mcp",
        headers=(),
        provenance=SourceProvenance(
            root / "mcp.json",
            "/mcpServers/remote-tools",
        ),
    )
    return AgentPlugin(
        specification_version="1.0.0",
        root=root,
        manifest=manifest,
        identity=AgentPluginIdentity(
            name="portable-plugin",
            version=version,
            description=None,
            author=(),
            homepage=None,
            repository="https://example.invalid/plugins/portable-plugin",
            license=None,
            keywords=(),
        ),
        components=AgentPluginComponents(
            skills=(skill,),
            mcp_servers=(stdio, remote),
        ),
        apm_extension=None,
        apm_configuration=None,
        diagnostics=(),
    )


def _stdio_component(plugin: AgentPlugin) -> ExecutableComponent:
    inventory = inventory_agent_plugin_executables(plugin)
    return next(
        component
        for component in inventory.components
        if component.kind == COMPONENT_KIND_MCP_STDIO
    )


def _asset(
    root: Path,
    path: str,
    *,
    mode: int = 0,
) -> AgentPluginAsset:
    return AgentPluginAsset(
        path=path,
        source=SourceProvenance(root / path, ""),
        sha256=ASSET_DIGEST,
        size=len(path),
        executable_mode=mode,
    )


def _apm_plugin(root: Path) -> AgentPlugin:
    plugin = _plugin(root)
    skill = plugin.components.skills[0]
    skill = replace(
        skill,
        assets=(
            *skill.assets,
            _asset(root, "skills/review/scripts/check.py", mode=0o100),
        ),
    )
    lsp_asset = _asset(root, "bin/lsp", mode=0o111)
    hook_asset = _asset(root, "bin/hook.sh", mode=0o100)
    lsp_provenance = SourceProvenance(
        root / "com.microsoft.apm" / "lsp.json",
        "/lspServers/python/command",
    )
    hook_provenance = SourceProvenance(
        root / "com.microsoft.apm" / "hooks" / "hooks.json",
        "/hooks/PreToolUse/0/hooks/0/command",
    )
    apm_components = ApmExtensionComponents(
        agents=ApmExtensionFileComponent(
            name="agents",
            root=root / "com.microsoft.apm" / "agents",
            provenance=SourceProvenance(root / "plugin.json", "/extensions/com.microsoft.apm"),
            assets=(_asset(root, "com.microsoft.apm/agents/reviewer.md"),),
        ),
        commands=ApmExtensionFileComponent(
            name="commands",
            root=root / "com.microsoft.apm" / "commands",
            provenance=SourceProvenance(root / "plugin.json", "/extensions/com.microsoft.apm"),
            assets=(_asset(root, "com.microsoft.apm/commands/review.md"),),
        ),
        instructions=ApmExtensionFileComponent(
            name="instructions",
            root=root / "com.microsoft.apm" / "instructions",
            provenance=SourceProvenance(root / "plugin.json", "/extensions/com.microsoft.apm"),
            assets=(_asset(root, "com.microsoft.apm/instructions/safe.md"),),
        ),
        extensions=ApmExtensionFileComponent(
            name="extensions",
            root=root / "com.microsoft.apm" / "extensions",
            provenance=SourceProvenance(root / "plugin.json", "/extensions/com.microsoft.apm"),
            assets=(_asset(root, "com.microsoft.apm/extensions/extension.mjs"),),
        ),
        hooks=ApmExtensionHookComponent(
            document=FrozenJsonObject(items=()),
            provenance=SourceProvenance(
                root / "com.microsoft.apm" / "hooks" / "hooks.json",
                "",
            ),
            executables=(
                AgentPluginExecutable(
                    declaration="${PLUGIN_ROOT}/bin/hook.sh",
                    plugin_relative_path="bin/hook.sh",
                    asset=hook_asset,
                    provenance=hook_provenance,
                ),
            ),
            assets=(
                _asset(root, "com.microsoft.apm/hooks/hooks.json"),
                hook_asset,
            ),
        ),
        lsp=ApmExtensionLspComponent(
            provenance=SourceProvenance(root / "com.microsoft.apm" / "lsp.json", ""),
            servers=(
                ApmExtensionLspServer(
                    name="python",
                    command="./bin/lsp",
                    args=("--stdio",),
                    env=(),
                    extension_to_language=((".py", "python"),),
                    transport=None,
                    initialization_options=None,
                    settings=None,
                    workspace_folder=None,
                    startup_timeout=None,
                    shutdown_timeout=None,
                    restart_on_crash=None,
                    max_restarts=None,
                    provenance=SourceProvenance(
                        root / "com.microsoft.apm" / "lsp.json",
                        "/lspServers/python",
                    ),
                    executables=(
                        AgentPluginExecutable(
                            declaration="./bin/lsp",
                            plugin_relative_path="bin/lsp",
                            asset=lsp_asset,
                            provenance=lsp_provenance,
                        ),
                    ),
                ),
            ),
            assets=(
                _asset(root, "com.microsoft.apm/lsp.json"),
                lsp_asset,
            ),
        ),
    )
    return replace(
        plugin,
        components=replace(plugin.components, skills=(skill,)),
        apm_components=apm_components,
    )


def test_inventory_classifies_portable_v1_components_without_ingress_paths(
    tmp_path: Path,
) -> None:
    inventory = inventory_agent_plugin_executables(_plugin(tmp_path / "archive-name"))

    assert inventory.failures == ()
    assert {
        (component.kind, component.classification, component.exec_type)
        for component in inventory.components
    } == {
        (COMPONENT_KIND_SKILL_ASSET, EXEC_CLASS_DECLARATIVE, None),
        (COMPONENT_KIND_MCP_STDIO, EXEC_CLASS_EXECUTABLE, EXEC_TYPE_MCP),
        (COMPONENT_KIND_MCP_REMOTE, EXEC_CLASS_DECLARATIVE, None),
    }
    assert {component.provenance for component in inventory.components} == {
        "skills/review/SKILL.md",
        "mcp.json#/mcpServers/local-tools/command",
        "mcp.json#/mcpServers/remote-tools",
    }
    executable = inventory.executable_components[0]
    assert executable.asset_state == ASSET_STATE_VERIFIED
    assert executable.plugin_relative_path == "bin/server"
    assert executable.asset_sha256 == ASSET_DIGEST
    assert executable.asset_size == 64
    assert executable.asset_executable_mode == 0o111


def test_inventory_covers_apm_extension_executable_surfaces(tmp_path: Path) -> None:
    inventory = inventory_agent_plugin_executables(_apm_plugin(tmp_path))

    assert inventory.failures == ()
    assert len(inventory.components) == 12
    assert {
        (component.kind, component.exec_type) for component in inventory.executable_components
    } == {
        (COMPONENT_KIND_SKILL_ASSET, EXEC_TYPE_BIN),
        (COMPONENT_KIND_MCP_STDIO, EXEC_TYPE_MCP),
        (COMPONENT_KIND_APM_EXTENSION, EXEC_TYPE_CANVAS),
        (COMPONENT_KIND_APM_HOOK, EXEC_TYPE_HOOKS),
        (COMPONENT_KIND_APM_LSP, EXEC_TYPE_LSP),
    }
    assert all(
        component.asset_state == ASSET_STATE_VERIFIED
        for component in inventory.executable_components
    )
    assert {component.provenance for component in inventory.executable_components} == {
        "skills/review/scripts/check.py",
        "mcp.json#/mcpServers/local-tools/command",
        "com.microsoft.apm/extensions/extension.mjs",
        "com.microsoft.apm/hooks/hooks.json#/hooks/PreToolUse/0/hooks/0/command",
        "com.microsoft.apm/lsp.json#/lspServers/python/command",
    }


def test_unknown_apm_asset_classification_fails_closed(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    agents = ApmExtensionFileComponent(
        name="agents",
        root=tmp_path / "com.microsoft.apm" / "agents",
        provenance=SourceProvenance(tmp_path / "plugin.json", "/extensions/com.microsoft.apm"),
        assets=(_asset(tmp_path, "com.microsoft.apm/agents/payload.wasm"),),
    )
    plugin = replace(
        plugin,
        apm_components=ApmExtensionComponents(
            agents=agents,
            commands=None,
            instructions=None,
            extensions=None,
            hooks=None,
            lsp=None,
        ),
    )

    evaluation = evaluate_agent_plugin_executable_trust(
        plugin,
        trust_context=_policy(project_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}}),
        source_facts=SOURCE_FACTS,
        explicit_consent=True,
    )

    assert len(evaluation.failures) == 1
    assert evaluation.failures[0].component_kind == "apm-agent"
    assert evaluation.failures[0].code == FAILURE_INVALID_COMPONENT


def test_trust_evaluation_does_not_reopen_verified_assets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_reopen(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("trust evaluation must not reopen package assets")

    monkeypatch.setattr(
        "apm_cli.agent_plugins.assets.open_verified_asset",
        reject_reopen,
    )

    evaluation = evaluate_agent_plugin_executable_trust(
        _apm_plugin(tmp_path),
        trust_context=_policy(
            project_allow={
                PLUGIN_KEY: {
                    EXEC_TYPE_BIN: True,
                    EXEC_TYPE_CANVAS: True,
                    EXEC_TYPE_HOOKS: True,
                    EXEC_TYPE_LSP: True,
                    EXEC_TYPE_MCP: True,
                }
            }
        ),
        source_facts=SOURCE_FACTS,
    )

    assert evaluation.failures == ()


def test_sse_mcp_is_declarative_remote_content(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    sse = replace(
        plugin.components.mcp_servers[1],
        name="legacy-remote",
        server_type=McpServerType.SSE,
        provenance=SourceProvenance(
            tmp_path / "mcp.json",
            "/mcpServers/legacy-remote",
        ),
    )
    plugin = replace(
        plugin,
        components=replace(plugin.components, mcp_servers=(sse,)),
    )

    evaluation = evaluate_agent_plugin_executable_trust(
        plugin,
        trust_context=_policy(),
        source_facts=SOURCE_FACTS,
    )

    result = next(
        item for item in evaluation.results if item.context.component.name == "legacy-remote"
    )
    assert result.context.component.kind == COMPONENT_KIND_MCP_REMOTE
    assert result.context.component.classification == EXEC_CLASS_DECLARATIVE
    assert result.decision.trust_state == TRUST_DECLARATIVE
    assert result.failure is None


def test_external_executable_remains_distinct_and_policy_controlled(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    server = plugin.components.mcp_servers[0]
    external = replace(
        server.executables[0],
        plugin_relative_path=None,
        asset=None,
        declaration="external-server",
    )
    plugin = replace(
        plugin,
        components=replace(
            plugin.components,
            mcp_servers=(replace(server, command="external-server", executables=(external,)),),
        ),
    )

    component = inventory_agent_plugin_executables(plugin).executable_components[0]
    result = resolve_agent_plugin_exec_decision(
        assemble_agent_plugin_exec_trust_context(
            _policy(project_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}}),
            plugin=plugin,
            component=component,
            source=SOURCE_FACTS,
        )
    )

    assert component.asset_state == ASSET_STATE_EXTERNAL
    assert component.plugin_relative_path is None
    assert component.asset_sha256 is None
    assert result.decision.allowed is True
    assert result.failure is None


def test_missing_package_executable_fails_closed_despite_consent(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    server = plugin.components.mcp_servers[0]
    missing = replace(server.executables[0], asset=None)
    plugin = replace(
        plugin,
        components=replace(
            plugin.components,
            mcp_servers=(replace(server, executables=(missing,)),),
        ),
    )

    component = inventory_agent_plugin_executables(plugin).executable_components[0]
    result = resolve_agent_plugin_exec_decision(
        assemble_agent_plugin_exec_trust_context(
            _policy(project_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}}),
            plugin=plugin,
            component=component,
            source=SOURCE_FACTS,
            explicit_consent=True,
        )
    )

    assert component.asset_state == ASSET_STATE_MISSING
    assert component.plugin_relative_path == "bin/server"
    assert component.asset_sha256 is None
    assert result.decision.allowed is False
    assert result.failure is not None
    assert result.failure.code == FAILURE_MISSING_ASSET


def test_malformed_verified_asset_facts_fail_closed(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    server = plugin.components.mcp_servers[0]
    malformed_asset = replace(server.executables[0].asset, sha256="")
    malformed = replace(server.executables[0], asset=malformed_asset)
    plugin = replace(
        plugin,
        components=replace(
            plugin.components,
            mcp_servers=(replace(server, executables=(malformed,)),),
        ),
    )

    evaluation = evaluate_agent_plugin_executable_trust(
        plugin,
        trust_context=_policy(project_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}}),
        source_facts=SOURCE_FACTS,
        explicit_consent=True,
    )

    assert len(evaluation.failures) == 1
    assert evaluation.failures[0].code == FAILURE_INVALID_PROVENANCE


def test_mismatched_executable_asset_path_fails_closed(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    server = plugin.components.mcp_servers[0]
    executable = server.executables[0]
    mismatch = replace(
        executable,
        asset=replace(executable.asset, path="bin/other"),
    )

    mismatched_plugin = replace(
        plugin,
        components=replace(
            plugin.components,
            mcp_servers=(replace(server, executables=(mismatch,)),),
        ),
    )
    evaluation = evaluate_agent_plugin_executable_trust(
        mismatched_plugin,
        trust_context=_policy(project_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}}),
        source_facts=SOURCE_FACTS,
        explicit_consent=True,
    )

    assert len(evaluation.failures) == 1
    assert evaluation.failures[0].code == FAILURE_INVALID_PROVENANCE


def test_multi_fact_launch_preserves_external_and_verified_states(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    server = plugin.components.mcp_servers[0]
    script_asset = _asset(tmp_path, "dist/index.js")
    runtime = AgentPluginExecutable(
        declaration="node",
        plugin_relative_path=None,
        asset=None,
        provenance=SourceProvenance(
            tmp_path / "mcp.json",
            "/mcpServers/local-tools/command",
        ),
    )
    script = AgentPluginExecutable(
        declaration="${PLUGIN_ROOT}/dist/index.js",
        plugin_relative_path="dist/index.js",
        asset=script_asset,
        provenance=SourceProvenance(
            tmp_path / "mcp.json",
            "/mcpServers/local-tools/args/0",
        ),
    )
    plugin = replace(
        plugin,
        components=replace(
            plugin.components,
            mcp_servers=(
                replace(
                    server,
                    command="node",
                    args=("${PLUGIN_ROOT}/dist/index.js", "--stdio"),
                    executables=(runtime, script),
                ),
            ),
        ),
    )

    evaluation = evaluate_agent_plugin_executable_trust(
        plugin,
        trust_context=_policy(project_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}}),
        source_facts=SOURCE_FACTS,
    )
    by_declaration = {result.context.component.declaration: result for result in evaluation.results}

    assert evaluation.failures == ()
    assert by_declaration["node"].context.component.asset_state == ASSET_STATE_EXTERNAL
    script_component = by_declaration["${PLUGIN_ROOT}/dist/index.js"].context.component
    assert script_component.asset_state == ASSET_STATE_VERIFIED
    assert script_component.asset_sha256 == ASSET_DIGEST
    assert script_component.command == "node"
    assert script_component.args == ("${PLUGIN_ROOT}/dist/index.js", "--stdio")


def test_traversal_in_recorded_component_provenance_fails_closed(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    server = plugin.components.mcp_servers[0]
    malformed = replace(
        server.executables[0],
        provenance=SourceProvenance(
            tmp_path / ".." / "outside.json",
            "/mcpServers/local-tools/command",
        ),
    )
    plugin = replace(
        plugin,
        components=replace(
            plugin.components,
            mcp_servers=(replace(server, executables=(malformed,)),),
        ),
    )

    evaluation = evaluate_agent_plugin_executable_trust(
        plugin,
        trust_context=_policy(project_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}}),
        source_facts=SOURCE_FACTS,
        explicit_consent=True,
    )

    assert len(evaluation.failures) == 1
    assert evaluation.failures[0].code == FAILURE_INVALID_PROVENANCE


def test_non_stdio_mcp_cannot_hide_executable_facts(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    stdio, remote = plugin.components.mcp_servers
    plugin = replace(
        plugin,
        components=replace(
            plugin.components,
            mcp_servers=(replace(remote, executables=stdio.executables),),
        ),
    )

    evaluation = evaluate_agent_plugin_executable_trust(
        plugin,
        trust_context=_policy(),
        source_facts=SOURCE_FACTS,
    )

    assert len(evaluation.failures) == 1
    assert evaluation.failures[0].code == FAILURE_INVALID_COMPONENT


@pytest.mark.parametrize(
    "ingress",
    ("directory", "archive", "git", "local", "registry", "marketplace"),
)
def test_equivalent_canonical_facts_produce_identical_decision_inputs(
    tmp_path: Path,
    ingress: str,
) -> None:
    policy = _policy(
        project_allow={
            PLUGIN_KEY: {
                EXEC_TYPE_BIN: True,
                EXEC_TYPE_CANVAS: True,
                EXEC_TYPE_HOOKS: True,
                EXEC_TYPE_LSP: True,
                EXEC_TYPE_MCP: True,
            }
        }
    )
    baseline_plugin = _apm_plugin(tmp_path / "baseline")
    baseline = tuple(
        assemble_agent_plugin_exec_trust_context(
            policy,
            plugin=baseline_plugin,
            component=component,
            source=SOURCE_FACTS,
        )
        for component in inventory_agent_plugin_executables(baseline_plugin).components
    )
    ingress_plugin = _apm_plugin(tmp_path / ingress / "materialized-basename")
    actual = tuple(
        assemble_agent_plugin_exec_trust_context(
            policy,
            plugin=ingress_plugin,
            component=component,
            source=SOURCE_FACTS,
        )
        for component in inventory_agent_plugin_executables(ingress_plugin).components
    )

    assert actual == baseline


@pytest.mark.parametrize(
    ("policy", "layer"),
    [
        (_policy(project_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}}), LAYER_PROJECT_ALLOW),
        (_policy(user_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}}), LAYER_USER_ALLOW),
    ],
)
def test_project_and_user_grants_use_existing_precedence(
    tmp_path: Path,
    policy: ExecTrustContext,
    layer: str,
) -> None:
    plugin = _plugin(tmp_path)
    context = assemble_agent_plugin_exec_trust_context(
        policy,
        plugin=plugin,
        component=_stdio_component(plugin),
        source=SOURCE_FACTS,
    )

    result = resolve_agent_plugin_exec_decision(context)

    assert result.decision.allowed is True
    assert result.decision.deciding_layer == layer
    assert result.failure is None


def test_explicit_consent_cannot_bypass_org_denial(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    context = assemble_agent_plugin_exec_trust_context(
        _policy(
            org_deny=frozenset({"portable-plugin"}),
            project_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}},
        ),
        plugin=plugin,
        component=_stdio_component(plugin),
        source=SOURCE_FACTS,
        explicit_consent=True,
    )

    result = resolve_agent_plugin_exec_decision(context)

    assert result.decision.allowed is False
    assert result.decision.deciding_layer == LAYER_ORG_DENY
    assert result.failure is not None
    assert result.failure.code == FAILURE_POLICY_DENIED


def test_explicit_consent_only_lifts_default_approval_gate(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    context = assemble_agent_plugin_exec_trust_context(
        _policy(),
        plugin=plugin,
        component=_stdio_component(plugin),
        source=SOURCE_FACTS,
        explicit_consent=True,
    )

    result = resolve_agent_plugin_exec_decision(context)

    assert result.decision.allowed is True
    assert result.decision.deciding_layer == LAYER_EXPLICIT_CONSENT


def test_default_and_gate_disabled_paths_remain_fail_closed(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    component = _stdio_component(plugin)

    for policy in (_policy(), _policy(gate_enabled=False)):
        result = resolve_agent_plugin_exec_decision(
            assemble_agent_plugin_exec_trust_context(
                policy,
                plugin=plugin,
                component=component,
                source=SOURCE_FACTS,
            )
        )
        assert result.decision.allowed is False
        assert result.failure is not None
        assert result.failure.code == FAILURE_APPROVAL_REQUIRED


@pytest.mark.parametrize(
    "source",
    (
        ExecSourceFacts(canonical_source=""),
        replace(SOURCE_FACTS, resolved_revision=""),
        replace(SOURCE_FACTS, content_digest=""),
        replace(SOURCE_FACTS, integrity_verified=False),
        replace(SOURCE_FACTS, signature_verified=False),
        replace(SOURCE_FACTS, integrity_verified=0),
        replace(SOURCE_FACTS, signature_verified="false"),
    ),
)
def test_malformed_or_failed_provenance_denies_even_with_consent(
    tmp_path: Path,
    source: ExecSourceFacts,
) -> None:
    plugin = _plugin(tmp_path)
    result = resolve_agent_plugin_exec_decision(
        assemble_agent_plugin_exec_trust_context(
            _policy(project_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}}),
            plugin=plugin,
            component=_stdio_component(plugin),
            source=source,
            explicit_consent=True,
        )
    )

    assert result.decision.allowed is False
    assert result.decision.trust_state == TRUST_DENIED
    assert result.failure is not None
    assert result.failure.code == FAILURE_INVALID_PROVENANCE


def test_empty_plugin_name_fails_closed(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    plugin = replace(plugin, identity=replace(plugin.identity, name=""))
    component = replace(_stdio_component(_plugin(tmp_path / "valid")), plugin_key="")

    result = resolve_agent_plugin_exec_decision(
        assemble_agent_plugin_exec_trust_context(
            _policy(project_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}}),
            plugin=plugin,
            component=component,
            source=SOURCE_FACTS,
            explicit_consent=True,
        )
    )

    assert result.decision.allowed is False
    assert result.failure is not None
    assert result.failure.code == FAILURE_INVALID_COMPONENT
    assert result.failure.deciding_layer == LAYER_INVALID_COMPONENT


def test_missing_version_and_unknown_component_identity_fail_closed(tmp_path: Path) -> None:
    versionless = _plugin(tmp_path, version=None)
    missing_version = resolve_agent_plugin_exec_decision(
        assemble_agent_plugin_exec_trust_context(
            _policy(project_allow={"portable-plugin": {EXEC_TYPE_MCP: True}}),
            plugin=versionless,
            component=_stdio_component(versionless),
            source=SOURCE_FACTS,
        )
    )
    unknown = replace(
        _stdio_component(_plugin(tmp_path / "known")),
        classification=EXEC_CLASS_UNKNOWN,
    )
    unknown_result = resolve_agent_plugin_exec_decision(
        assemble_agent_plugin_exec_trust_context(
            _policy(project_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}}),
            plugin=_plugin(tmp_path / "known"),
            component=unknown,
            source=SOURCE_FACTS,
        )
    )
    mismatched = replace(_stdio_component(_plugin(tmp_path / "mismatch")), plugin_key="attacker#9")
    mismatch_result = resolve_agent_plugin_exec_decision(
        assemble_agent_plugin_exec_trust_context(
            _policy(project_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}}),
            plugin=_plugin(tmp_path / "mismatch"),
            component=mismatched,
            source=SOURCE_FACTS,
        )
    )

    assert missing_version.failure is not None
    assert missing_version.failure.code == FAILURE_INVALID_COMPONENT
    assert unknown_result.failure is not None
    assert unknown_result.failure.code == FAILURE_INVALID_COMPONENT
    assert unknown_result.decision.deciding_layer == LAYER_INVALID_COMPONENT
    assert mismatch_result.failure is not None
    assert mismatch_result.failure.code == FAILURE_INVALID_COMPONENT


def test_non_boolean_explicit_consent_fails_closed(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    context = assemble_agent_plugin_exec_trust_context(
        _policy(),
        plugin=plugin,
        component=_stdio_component(plugin),
        source=SOURCE_FACTS,
        explicit_consent="false",
    )

    result = resolve_agent_plugin_exec_decision(context)

    assert result.decision.allowed is False
    assert result.failure is not None
    assert result.failure.code == FAILURE_INVALID_COMPONENT
    assert result.failure.deciding_layer == LAYER_INVALID_COMPONENT


def test_unknown_canonical_mcp_transport_fails_closed(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    unknown_server = replace(
        plugin.components.mcp_servers[0],
        server_type="future-transport",
    )
    plugin = replace(
        plugin,
        components=replace(plugin.components, mcp_servers=(unknown_server,)),
    )

    evaluation = evaluate_agent_plugin_executable_trust(
        plugin,
        trust_context=_policy(project_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}}),
        source_facts=SOURCE_FACTS,
        explicit_consent=True,
    )

    assert len(evaluation.failures) == 1
    assert evaluation.failures[0].code == FAILURE_INVALID_COMPONENT


def test_exec_gate_facade_returns_typed_failures_without_mutation(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    before = tuple(sorted(tmp_path.rglob("*")))

    evaluation = evaluate_agent_plugin_executable_trust(
        plugin,
        trust_context=_policy(),
        source_facts=SOURCE_FACTS,
    )

    assert len(evaluation.inventory.components) == 3
    assert len(evaluation.failures) == 1
    assert evaluation.failures[0].component_kind == COMPONENT_KIND_MCP_STDIO
    assert {
        result.decision.trust_state
        for result in evaluation.results
        if result.context.component.classification == EXEC_CLASS_DECLARATIVE
    } == {TRUST_DECLARATIVE}
    assert tuple(sorted(tmp_path.rglob("*"))) == before
