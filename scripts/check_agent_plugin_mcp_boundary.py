#!/usr/bin/env python3
"""Enforce the canonical native Agent Plugin MCP preparation boundary."""

from __future__ import annotations

import argparse
import ast
from pathlib import Path

FACADE_PATH = Path("src/apm_cli/install/mcp/integration.py")
PROJECTOR_PATH = Path("src/apm_cli/integration/mcp_integrator_native.py")
MODEL_PATH = Path("src/apm_cli/models/dependency/native_mcp.py")

_FORBIDDEN_CALLS = frozenset(
    {
        "APMPackage.from_mapping",
        "AuthResolver",
        "DeploymentLedgerCodec.replace_mcp_target_servers",
        "MCPDependency.from_dict",
        "MCPIntegrator._build_self_defined_info",
        "MCPIntegrator.install",
        "MCPIntegrator.remove_stale",
        "MCPIntegrator.update_lockfile",
        "_build_self_defined_info",
        "detect_agent_plugin",
        "expandvars",
        "json.load",
        "json.loads",
        "load_agent_plugin",
        "open",
        "os.getenv",
        "os.path.expandvars",
        "read_bytes",
        "read_json_document",
        "read_text",
        "save",
        "unquote",
        "urlparse",
        "validate_mcp_config_file",
        "write",
        "write_bytes",
        "write_text",
        "yaml.safe_load",
    }
)
_AMBIENT_CREDENTIAL_NAMES = frozenset(
    {
        "ADO_APM_PAT",
        "GH_TOKEN",
        "GITHUB_APM_PAT",
        "GITHUB_TOKEN",
    }
)


def _call_name(node: ast.AST) -> str:
    current = node.func if isinstance(node, ast.Call) else node
    parts: list[str] = []
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _shape(node: ast.AST) -> str:
    return ast.dump(node, include_attributes=False)


def _expression(source: str) -> ast.expr:
    return ast.parse(source, mode="eval").body


def _find_function(tree: ast.Module, name: str) -> ast.FunctionDef | None:
    matches = [
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    return matches[0] if len(matches) == 1 else None


def _named_assignment(function: ast.FunctionDef, name: str) -> ast.expr | None:
    matches = [
        node.value
        for node in function.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == name
    ]
    return matches[0] if len(matches) == 1 else None


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    matches = [keyword.value for keyword in call.keywords if keyword.arg == name]
    return matches[0] if len(matches) == 1 else None


def _single_call(function: ast.FunctionDef, name: str) -> ast.Call | None:
    matches = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and _call_name(node) == name
    ]
    return matches[0] if len(matches) == 1 else None


def _attribute_chain(node: ast.AST, chain: str) -> bool:
    return _call_name(node) == chain


def _boundary_violations(
    function: ast.FunctionDef,
    path: Path,
    *,
    allowed_calls: frozenset[str],
) -> list[str]:
    violations: list[str] = []
    calls = {_call_name(node) for node in ast.walk(function) if isinstance(node, ast.Call)}
    forbidden = sorted(calls & _FORBIDDEN_CALLS)
    if forbidden:
        violations.append(
            f"{path}:{function.lineno}: native MCP preparation must not reparse, "
            f"normalize legacy MCP, resolve auth, or rewrite URLs: {', '.join(forbidden)}"
        )
    ambient_names = sorted(
        {
            node.value
            for node in ast.walk(function)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in _AMBIENT_CREDENTIAL_NAMES
        }
    )
    if ambient_names:
        violations.append(
            f"{path}:{function.lineno}: native MCP preparation must not name ambient "
            f"credential channels: {', '.join(ambient_names)}"
        )
    unexpected = sorted(calls - allowed_calls)
    if unexpected:
        violations.append(
            f"{path}:{function.lineno}: native MCP preparation pure-call allowlist rejected: "
            f"{', '.join(unexpected)}"
        )
    return violations


def _check_facade(tree: ast.Module, path: Path) -> list[str]:
    function = _find_function(tree, "prepare_attached_agent_plugin_mcp")
    if function is None:
        return [f"{path}: attached Agent Plugin MCP preparation facade must have one definition"]
    violations = _boundary_violations(
        function,
        path,
        allowed_calls=frozenset({"ValueError", "prepare_agent_plugin_mcp_servers"}),
    )
    plugin_value = _named_assignment(function, "plugin")
    if plugin_value is None or not _attribute_chain(
        plugin_value,
        "package_info.package.agent_plugin",
    ):
        violations.append(
            f"{path}:{function.lineno}: native MCP preparation must consume package_info.package."
            "agent_plugin directly"
        )
    projection = _single_call(function, "prepare_agent_plugin_mcp_servers")
    if (
        projection is None
        or len(projection.args) != 1
        or not isinstance(projection.args[0], ast.Name)
        or projection.args[0].id != "plugin"
        or _shape(_keyword(projection, "plugin_root") or ast.Constant(None))
        != _shape(_expression("plugin_root"))
        or _shape(_keyword(projection, "plugin_data") or ast.Constant(None))
        != _shape(_expression("plugin_data"))
    ):
        violations.append(
            f"{path}:{function.lineno}: attached IR must route directly to the native MCP projector"
        )
    return violations


def _check_placeholder_owner(tree: ast.Module, path: Path) -> list[str]:
    expected = r"\$\{(?P<name>PLUGIN_ROOT|PLUGIN_DATA)\}"
    matches = [
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "_AGENT_PLUGIN_MCP_PLACEHOLDER"
        and isinstance(node.value, ast.Call)
        and _call_name(node.value) == "re.compile"
        and len(node.value.args) == 1
        and isinstance(node.value.args[0], ast.Constant)
        and node.value.args[0].value == expected
    ]
    if len(matches) != 1:
        return [f"{path}: native MCP placeholder owner must match only PLUGIN_ROOT and PLUGIN_DATA"]
    return []


def _check_projector_imports(tree: ast.Module, path: Path) -> list[str]:
    allowed_modules = {
        "__future__",
        "apm_cli.agent_plugins.ir",
        "apm_cli.models.dependency.native_mcp",
        "pathlib",
        "re",
        "typing",
    }
    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_modules.add(node.module)
    unexpected = sorted(imported_modules - allowed_modules)
    if unexpected:
        return [f"{path}: native MCP projector import allowlist rejected: {', '.join(unexpected)}"]
    return []


def _check_module_calls(
    tree: ast.Module,
    path: Path,
    *,
    allowed_calls: frozenset[str],
) -> list[str]:
    calls = {_call_name(node) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    unexpected = sorted(calls - allowed_calls)
    if unexpected:
        return [f"{path}: native MCP module pure-call allowlist rejected: {', '.join(unexpected)}"]
    return []


def _check_projector(tree: ast.Module, path: Path) -> list[str]:
    function = _find_function(tree, "prepare_agent_plugin_mcp_servers")
    per_server = _find_function(tree, "_prepare_agent_plugin_mcp_server")
    expand = _find_function(tree, "_expand_agent_plugin_mcp_value")
    if function is None or per_server is None or expand is None:
        return [
            f"{path}: native Agent Plugin MCP projector functions must each have one definition"
        ]
    violations = _check_placeholder_owner(tree, path)
    violations.extend(_check_projector_imports(tree, path))
    violations.extend(
        _check_module_calls(
            tree,
            path,
            allowed_calls=frozenset(
                {
                    "AgentPluginMCPPreparation",
                    "AgentPluginMCPPreparationSuccess",
                    "AgentPluginMCPProvenance",
                    "AgentPluginMCPServerConfig",
                    "AgentPluginMCPServerProvenance",
                    "_AGENT_PLUGIN_MCP_PLACEHOLDER.sub",
                    "_expand_agent_plugin_mcp_value",
                    "_prepare_agent_plugin_mcp_server",
                    "match.group",
                    "re.compile",
                    "str",
                    "tuple",
                }
            ),
        )
    )
    violations.extend(
        _boundary_violations(
            expand,
            path,
            allowed_calls=frozenset(
                {
                    "_AGENT_PLUGIN_MCP_PLACEHOLDER.sub",
                    "match.group",
                }
            ),
        )
    )
    violations.extend(
        _boundary_violations(
            function,
            path,
            allowed_calls=frozenset(
                {
                    "AgentPluginMCPPreparation",
                    "AgentPluginMCPProvenance",
                    "_prepare_agent_plugin_mcp_server",
                    "str",
                    "tuple",
                }
            ),
        )
    )
    violations.extend(
        _boundary_violations(
            per_server,
            path,
            allowed_calls=frozenset(
                {
                    "AgentPluginMCPPreparationSuccess",
                    "AgentPluginMCPServerConfig",
                    "AgentPluginMCPServerProvenance",
                    "_expand_agent_plugin_mcp_value",
                    "tuple",
                }
            ),
        )
    )

    provenance_call = _single_call(function, "AgentPluginMCPProvenance")
    expected_provenance = {
        "specification_version": "plugin.specification_version",
        "plugin_name": "plugin.identity.name",
        "plugin_version": "plugin.identity.version",
        "source_root": "plugin.root",
        "manifest": "plugin.manifest",
    }
    if provenance_call is None or any(
        _shape(_keyword(provenance_call, name) or ast.Constant(None))
        != _shape(_expression(expected))
        for name, expected in expected_provenance.items()
    ):
        violations.append(
            f"{path}:{function.lineno}: plugin identity, version, root, and manifest provenance "
            "must survive native MCP preparation"
        )

    server_provenance = _single_call(per_server, "AgentPluginMCPServerProvenance")
    if (
        server_provenance is None
        or _shape(_keyword(server_provenance, "plugin") or ast.Constant(None))
        != _shape(_expression("provenance"))
        or _shape(_keyword(server_provenance, "declaration") or ast.Constant(None))
        != _shape(_expression("server.provenance"))
    ):
        violations.append(
            f"{path}:{per_server.lineno}: each native MCP server must retain plugin and "
            "declaration provenance"
        )

    config_call = _single_call(per_server, "AgentPluginMCPServerConfig")
    if config_call is None:
        violations.append(f"{path}:{per_server.lineno}: native MCP config projection is missing")
        return violations
    expected_literals = {
        "name": "server.name",
        "server_type": "server.server_type",
        "command": "server.command",
        "url": "server.url",
        "headers": "server.headers",
        "provenance": "server_provenance",
    }
    if any(
        _shape(_keyword(config_call, name) or ast.Constant(None)) != _shape(_expression(expected))
        for name, expected in expected_literals.items()
    ):
        violations.append(
            f"{path}:{per_server.lineno}: native MCP command, URL, headers, type, name, and "
            "provenance must be copied literally"
        )

    expected_expansions = {
        "args": """tuple(
            _expand_agent_plugin_mcp_value(
                value,
                plugin_root=plugin_root,
                plugin_data=plugin_data,
            )
            for value in server.args
        )""",
        "env": """tuple(
            (
                name,
                _expand_agent_plugin_mcp_value(
                    value,
                    plugin_root=plugin_root,
                    plugin_data=plugin_data,
                ),
            )
            for name, value in server.env
        )""",
        "cwd": """(
            _expand_agent_plugin_mcp_value(
                server.cwd,
                plugin_root=plugin_root,
                plugin_data=plugin_data,
            )
            if server.cwd is not None
            else None
        )""",
    }
    if any(
        _shape(_keyword(config_call, name) or ast.Constant(None)) != _shape(_expression(expected))
        for name, expected in expected_expansions.items()
    ):
        violations.append(
            f"{path}:{per_server.lineno}: only args, env values, and cwd may expand native "
            "MCP path placeholders"
        )
    return violations


def _check_models(tree: ast.Module, path: Path) -> list[str]:
    required = {
        "AgentPluginMCPPreparation",
        "AgentPluginMCPPreparationFailure",
        "AgentPluginMCPPreparationSuccess",
        "AgentPluginMCPProvenance",
        "AgentPluginMCPServerConfig",
        "AgentPluginMCPServerProvenance",
    }
    classes = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
    missing = sorted(required - classes)
    if missing:
        return [f"{path}: native MCP typed preparation models are missing: {', '.join(missing)}"]
    violations = _check_module_calls(
        tree,
        path,
        allowed_calls=frozenset({"dataclass", "field", "isinstance", "tuple"}),
    )
    allowed_modules = {
        "__future__",
        "apm_cli.agent_plugins.ir",
        "dataclasses",
        "pathlib",
        "typing",
    }
    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_modules.add(node.module)
    unexpected_imports = sorted(imported_modules - allowed_modules)
    if unexpected_imports:
        violations.append(
            f"{path}: native MCP model import allowlist rejected: {', '.join(unexpected_imports)}"
        )
    return violations


def check(root: Path) -> list[str]:
    """Return native Agent Plugin MCP boundary violations."""
    paths = (FACADE_PATH, PROJECTOR_PATH, MODEL_PATH)
    trees: dict[Path, ast.Module] = {}
    violations: list[str] = []
    for relative in paths:
        path = root / relative
        try:
            trees[relative] = ast.parse(path.read_text(encoding="utf-8"), filename=str(relative))
        except (OSError, SyntaxError) as exc:
            violations.append(f"{relative}: cannot inspect native MCP owner: {exc}")
    if violations:
        return violations
    violations.extend(_check_facade(trees[FACADE_PATH], FACADE_PATH))
    violations.extend(_check_projector(trees[PROJECTOR_PATH], PROJECTOR_PATH))
    violations.extend(_check_models(trees[MODEL_PATH], MODEL_PATH))
    return violations


def main() -> int:
    """Run the native Agent Plugin MCP boundary check."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    violations = check(args.root)
    for violation in violations:
        print(f"[x] {violation}")
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
