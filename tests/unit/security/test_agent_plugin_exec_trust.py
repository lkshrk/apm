"""Component-granular executable trust contracts for Agent Plugins."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from apm_cli.agent_plugins.ir import (
    AgentPlugin,
    AgentPluginComponents,
    AgentPluginIdentity,
    AgentPluginMcpServer,
    AgentPluginSkill,
    McpServerType,
    SourceProvenance,
)
from apm_cli.install.exec_gate import evaluate_agent_plugin_executable_trust
from apm_cli.security.executables import (
    COMPONENT_KIND_MCP_REMOTE,
    COMPONENT_KIND_MCP_STDIO,
    EXEC_CLASS_DECLARATIVE,
    EXEC_CLASS_EXECUTABLE,
    EXEC_CLASS_UNKNOWN,
    EXEC_TYPE_MCP,
    FAILURE_APPROVAL_REQUIRED,
    FAILURE_INVALID_COMPONENT,
    FAILURE_INVALID_PROVENANCE,
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
    skill = AgentPluginSkill(
        directory_name="review",
        name="review",
        description="Review a change",
        root=root / "skills" / "review",
        manifest=SourceProvenance(root / "skills" / "review" / "SKILL.md", ""),
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
        provenance=SourceProvenance(
            root / "mcp.json",
            "/mcpServers/local-tools",
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


def test_inventory_classifies_portable_v1_components_without_ingress_paths(
    tmp_path: Path,
) -> None:
    inventory = inventory_agent_plugin_executables(_plugin(tmp_path / "archive-name"))

    assert inventory.failures == ()
    assert [
        (component.kind, component.classification, component.exec_type)
        for component in inventory.components
    ] == [
        (COMPONENT_KIND_MCP_STDIO, EXEC_CLASS_EXECUTABLE, EXEC_TYPE_MCP),
        (COMPONENT_KIND_MCP_REMOTE, EXEC_CLASS_DECLARATIVE, None),
        ("skill", EXEC_CLASS_DECLARATIVE, None),
    ]
    assert {component.provenance for component in inventory.components} == {
        "skills/review/SKILL.md",
        "mcp.json#/mcpServers/local-tools",
        "mcp.json#/mcpServers/remote-tools",
    }


@pytest.mark.parametrize(
    "ingress",
    ("directory", "archive", "git", "local", "registry", "marketplace"),
)
def test_equivalent_canonical_facts_produce_identical_decision_inputs(
    tmp_path: Path,
    ingress: str,
) -> None:
    baseline_plugin = _plugin(tmp_path / "baseline")
    baseline_component = _stdio_component(baseline_plugin)
    baseline = assemble_agent_plugin_exec_trust_context(
        _policy(project_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}}),
        plugin=baseline_plugin,
        component=baseline_component,
        source=SOURCE_FACTS,
    )
    ingress_plugin = _plugin(tmp_path / ingress / "materialized-basename")
    actual = assemble_agent_plugin_exec_trust_context(
        _policy(project_allow={PLUGIN_KEY: {EXEC_TYPE_MCP: True}}),
        plugin=ingress_plugin,
        component=_stdio_component(ingress_plugin),
        source=SOURCE_FACTS,
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
