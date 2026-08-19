"""Architecture guards for native Agent Plugin MCP preparation."""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path
from types import ModuleType

import pytest


def _checker(root: Path) -> ModuleType:
    path = root / "scripts/check_agent_plugin_mcp_boundary.py"
    spec = importlib.util.spec_from_file_location("check_agent_plugin_mcp_boundary", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_native_agent_plugin_mcp_has_static_boundary() -> None:
    root = Path(__file__).parents[2]
    guard = (root / "scripts/lint-architecture-boundaries.sh").read_text(encoding="utf-8")
    checker = _checker(root)

    assert checker.check(root) == []
    assert "AC34: native Agent Plugin MCP preparation authority" in guard
    assert (
        "Native Agent Plugin MCP preparation must remain IR-only, literal, "
        "credential-isolated, write-free, and provenance-complete" in guard
    )


@pytest.mark.parametrize(
    ("relative_path", "old", "new", "message"),
    (
        (
            "src/apm_cli/install/mcp/integration.py",
            "    plugin = package_info.package.agent_plugin",
            "    plugin = load_agent_plugin(package_info.install_path)",
            "must consume package_info.package.agent_plugin directly",
        ),
        (
            "src/apm_cli/install/mcp/integration.py",
            "    if plugin is None:\n"
            "        from apm_cli.agent_plugins.errors import (\n"
            "            AGENT_PLUGIN_IR_MISSING,\n"
            "            AgentPluginDeploymentBoundaryError,\n"
            "        )\n\n"
            "        raise AgentPluginDeploymentBoundaryError(AGENT_PLUGIN_IR_MISSING)",
            "    if plugin is None:\n        pass",
            "missing attached Agent Plugin IR must raise",
        ),
        (
            "src/apm_cli/install/mcp/integration.py",
            "        raise AgentPluginDeploymentBoundaryError(AGENT_PLUGIN_IR_MISSING)",
            '        raise AttributeError("agent_plugin")',
            "missing attached Agent Plugin IR must raise",
        ),
        (
            "src/apm_cli/integration/mcp_integrator_native.py",
            'r"\\$\\{(?P<name>PLUGIN_ROOT|PLUGIN_DATA)\\}"',
            'r"\\$\\{(?P<name>[^}]+)\\}"',
            "must match only PLUGIN_ROOT and PLUGIN_DATA",
        ),
        (
            "src/apm_cli/integration/mcp_integrator_native.py",
            "        url=server.url,",
            "        url=server.url.strip(),",
            "must be copied literally",
        ),
        (
            "src/apm_cli/integration/mcp_integrator_native.py",
            "        headers=server.headers,",
            '        headers=server.headers + (("Authorization", os.getenv("GITHUB_TOKEN")),),',
            "must be copied literally",
        ),
        (
            "src/apm_cli/integration/mcp_integrator_native.py",
            "        declaration=server.provenance,",
            "        declaration=plugin.manifest,",
            "must retain plugin and declaration provenance",
        ),
        (
            "src/apm_cli/integration/mcp_integrator_native.py",
            '    """Prepare immutable native MCP facts from one canonical Agent Plugin IR."""',
            '    """Prepare immutable native MCP facts from one canonical Agent Plugin IR."""\n'
            "    MCPDependency.from_dict({})",
            "must not reparse, normalize legacy MCP, resolve auth, or rewrite URLs",
        ),
        (
            "src/apm_cli/integration/mcp_integrator_native.py",
            '    """Prepare immutable native MCP facts from one canonical Agent Plugin IR."""',
            '    """Prepare immutable native MCP facts from one canonical Agent Plugin IR."""\n'
            '    Path("config.json").write_text("mutated")',
            "pure-call allowlist rejected",
        ),
        (
            "src/apm_cli/integration/mcp_integrator_native.py",
            "_AGENT_PLUGIN_MCP_PLACEHOLDER = re.compile("
            'r"\\$\\{(?P<name>PLUGIN_ROOT|PLUGIN_DATA)\\}")',
            "_AGENT_PLUGIN_MCP_PLACEHOLDER = re.compile("
            'r"\\$\\{(?P<name>PLUGIN_ROOT|PLUGIN_DATA)\\}")\n'
            'Path("module-config.json").write_text("mutated")',
            "module pure-call allowlist rejected",
        ),
        (
            "src/apm_cli/models/dependency/native_mcp.py",
            "from apm_cli.agent_plugins.ir import "
            "AgentPluginExecutable, McpServerType, SourceProvenance",
            "from apm_cli.agent_plugins.ir import "
            "AgentPluginExecutable, McpServerType, SourceProvenance\n"
            'Path("model-config.json").write_text("mutated")',
            "module pure-call allowlist rejected",
        ),
        (
            "src/apm_cli/integration/mcp_integrator_native.py",
            "        command=server.command,",
            "        command=_expand_agent_plugin_mcp_value("
            "server.command, plugin_root=plugin_root, plugin_data=plugin_data),",
            "must be copied literally",
        ),
        (
            "src/apm_cli/integration/mcp_integrator_native.py",
            "        executables=server.executables,",
            "        executables=(),",
            "executable facts",
        ),
        (
            "src/apm_cli/install/local_bundle_handler.py",
            "        if not is_agent_plugin:\n            bundle_mcp_declared = False",
            "        if is_agent_plugin:\n            bundle_mcp_declared = False",
            "must not reach or alias legacy MCP interpretation",
        ),
        (
            "src/apm_cli/install/local_bundle_handler.py",
            "        if not is_agent_plugin and bundle_mcp_present "
            "and bundle_info.source_dir is not None:",
            "        if is_agent_plugin and bundle_mcp_present "
            "and bundle_info.source_dir is not None:",
            "must not reach or alias legacy MCP interpretation",
        ),
        (
            "src/apm_cli/install/local_bundle_handler.py",
            "    runtime_root: Path | None = None,\n) -> list[MCPDependency]:",
            "    runtime_root: Path | None = None,\n"
            "    agent_plugin: bool = False,\n"
            ") -> list[MCPDependency]:",
            "must not accept a native Agent Plugin mode",
        ),
        (
            "src/apm_cli/install/local_bundle_handler.py",
            '        is_agent_plugin = getattr(bundle_info, "format", "") '
            "== BundleFormat.AGENT_PLUGIN.value",
            "        is_agent_plugin = False",
            "native classification must use BundleFormat.AGENT_PLUGIN",
        ),
        (
            "src/apm_cli/install/local_bundle_handler.py",
            "        enforce_agent_plugin_deployment_boundary(bundle_info=bundle_info)",
            "        enforce_agent_plugin_deployment_boundary(bundle_info=bundle_info)\n"
            "        MCPDependency.from_dict({})",
            "must remain inside the legacy-only",
        ),
        (
            "src/apm_cli/install/local_bundle_handler.py",
            "        enforce_agent_plugin_deployment_boundary(bundle_info=bundle_info)",
            "        enforce_agent_plugin_deployment_boundary(bundle_info=bundle_info)\n"
            "        AuthResolver()",
            "must not resolve or name ambient credentials",
        ),
        (
            "src/apm_cli/install/local_bundle_handler.py",
            "        enforce_agent_plugin_deployment_boundary(bundle_info=bundle_info)",
            "        enforce_agent_plugin_deployment_boundary(bundle_info=bundle_info)\n"
            '        os.getenv("GITHUB_PERSONAL_ACCESS_TOKEN")',
            "must not resolve or name ambient credentials",
        ),
        (
            "src/apm_cli/install/local_bundle_handler.py",
            "        enforce_agent_plugin_deployment_boundary(bundle_info=bundle_info)",
            "        enforce_agent_plugin_deployment_boundary(bundle_info=bundle_info)\n"
            "        legacy_parser = _parse_legacy_bundle_mcp_servers",
            "must not reach or alias legacy MCP interpretation",
        ),
        (
            "src/apm_cli/install/local_bundle_handler.py",
            "    _require_legacy_bundle_mcp_format(bundle_format)\n"
            "    from urllib.parse import urlparse",
            "    from urllib.parse import urlparse",
            "must reject native format before interpretation or writes",
        ),
        (
            "src/apm_cli/install/local_bundle_handler.py",
            "    _require_legacy_bundle_mcp_format(bundle_format)\n"
            "    if not deps and owner is None:",
            "    if not deps and owner is None:",
            "must reject native format before interpretation or writes",
        ),
        (
            "src/apm_cli/install/local_bundle_handler.py",
            "    if bundle_format == BundleFormat.AGENT_PLUGIN.value:",
            "    if bundle_format == BundleFormat.CLAUDE_PLUGIN.value:",
            "must reject BundleFormat.AGENT_PLUGIN",
        ),
        (
            "src/apm_cli/install/local_bundle_handler.py",
            "    if bundle_format != BundleFormat.CLAUDE_PLUGIN.value:",
            "    if bundle_format != BundleFormat.APM.value:",
            "allow only BundleFormat.CLAUDE_PLUGIN",
        ),
        (
            "src/apm_cli/install/local_bundle_handler.py",
            "    if not deps and owner is None:",
            "    deps = _parse_legacy_bundle_mcp_servers(\n"
            "        Path('.'), bundle_format=bundle_format\n"
            "    )\n"
            "    if not deps and owner is None:",
            "must not reach or alias legacy MCP interpretation",
        ),
        (
            "src/apm_cli/adapters/client/agent_plugin_projection.py",
            "        server = result.config",
            "        server = plugin.components.mcp_servers[0]",
            "must consume T6 preparation configs",
        ),
        (
            "src/apm_cli/adapters/client/agent_plugin_projection.py",
            "                preparation=result,",
            "                preparation=mcp_preparation.successes[0],",
            "typed preparation",
        ),
        (
            "src/apm_cli/adapters/client/agent_plugin_projection.py",
            "                    preparation=result,",
            "                    preparation=None,",
            "diagnostics must retain their typed preparation",
        ),
        (
            "src/apm_cli/adapters/client/agent_plugin_projection.py",
            "from ...models.dependency.native_mcp import (",
            "from apm_cli.install.local_bundle_handler import "
            "_parse_legacy_bundle_mcp_servers\n"
            "from ...models.dependency.native_mcp import (",
            "is legacy-only and must not gain external",
        ),
    ),
)
def test_native_agent_plugin_mcp_guard_rejects_semantic_mutations(
    tmp_path: Path,
    relative_path: str,
    old: str,
    new: str,
    message: str,
) -> None:
    root = Path(__file__).parents[2]
    sandbox = tmp_path / "repo"
    paths = (
        "src/apm_cli/install/mcp/integration.py",
        "src/apm_cli/integration/mcp_integrator_native.py",
        "src/apm_cli/models/dependency/native_mcp.py",
        "src/apm_cli/install/local_bundle_handler.py",
        "src/apm_cli/adapters/client/agent_plugin_projection.py",
    )
    for relative in paths:
        destination = sandbox / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / relative, destination)
    mutation = sandbox / relative_path
    source = mutation.read_text(encoding="utf-8")
    assert old in source
    mutation.write_text(source.replace(old, new, 1), encoding="utf-8")

    violations = _checker(root).check(sandbox)

    assert any(message in violation for violation in violations)
