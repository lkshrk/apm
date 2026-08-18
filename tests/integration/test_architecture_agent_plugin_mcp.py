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
            "from apm_cli.agent_plugins.ir import McpServerType, SourceProvenance",
            "from apm_cli.agent_plugins.ir import McpServerType, SourceProvenance\n"
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
