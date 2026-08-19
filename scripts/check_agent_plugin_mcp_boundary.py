#!/usr/bin/env python3
"""Enforce the canonical native Agent Plugin MCP preparation boundary."""

from __future__ import annotations

import argparse
import ast
from pathlib import Path

FACADE_PATH = Path("src/apm_cli/install/mcp/integration.py")
PROJECTOR_PATH = Path("src/apm_cli/integration/mcp_integrator_native.py")
MODEL_PATH = Path("src/apm_cli/models/dependency/native_mcp.py")
LOCAL_BUNDLE_PATH = Path("src/apm_cli/install/local_bundle_handler.py")

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
        "GITHUB_PERSONAL_ACCESS_TOKEN",
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


def _test_excludes_native_agent_plugin(node: ast.AST) -> bool:
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.Not)
        and isinstance(node.operand, ast.Name)
        and node.operand.id == "is_agent_plugin"
    ):
        return True
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        return any(_test_excludes_native_agent_plugin(value) for value in node.values)
    return False


def _parent_fields(tree: ast.AST) -> dict[ast.AST, tuple[ast.AST, str]]:
    parents: dict[ast.AST, tuple[ast.AST, str]] = {}
    for parent in ast.walk(tree):
        for field, value in ast.iter_fields(parent):
            children = value if isinstance(value, list) else [value]
            for child in children:
                if isinstance(child, ast.AST):
                    parents[child] = (parent, field)
    return parents


def _enclosing_function(
    node: ast.AST,
    parents: dict[ast.AST, tuple[ast.AST, str]],
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    current = node
    while current in parents:
        parent, _field = parents[current]
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return parent
        current = parent
    return None


def _first_statement_after_docstring(function: ast.FunctionDef) -> ast.stmt | None:
    body = function.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    return body[0] if body else None


def _is_legacy_guarded(
    node: ast.AST,
    function: ast.FunctionDef,
    parents: dict[ast.AST, tuple[ast.AST, str]],
) -> bool:
    current = node
    while current is not function and current in parents:
        parent, field = parents[current]
        if (
            isinstance(parent, ast.If)
            and field == "body"
            and _test_excludes_native_agent_plugin(parent.test)
        ):
            return True
        current = parent
    return False


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
        allowed_calls=frozenset(
            {
                "AgentPluginDeploymentBoundaryError",
                "prepare_agent_plugin_mcp_servers",
            }
        ),
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
    missing_ir_guards = [
        node
        for node in function.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "plugin"
        and len(node.test.ops) == 1
        and isinstance(node.test.ops[0], ast.Is)
        and len(node.test.comparators) == 1
        and isinstance(node.test.comparators[0], ast.Constant)
        and node.test.comparators[0].value is None
    ]
    typed_missing_ir_raises = []
    if len(missing_ir_guards) == 1:
        typed_missing_ir_raises = [
            node
            for node in ast.walk(missing_ir_guards[0])
            if isinstance(node, ast.Raise)
            and isinstance(node.exc, ast.Call)
            and _call_name(node.exc) == "AgentPluginDeploymentBoundaryError"
            and len(node.exc.args) == 1
            and isinstance(node.exc.args[0], ast.Name)
            and node.exc.args[0].id == "AGENT_PLUGIN_IR_MISSING"
        ]
    if len(missing_ir_guards) != 1 or len(typed_missing_ir_raises) != 1:
        violations.append(
            f"{path}:{function.lineno}: missing attached Agent Plugin IR must raise "
            "AgentPluginDeploymentBoundaryError with AGENT_PLUGIN_IR_MISSING"
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
        "executables": "server.executables",
        "provenance": "server_provenance",
    }
    if any(
        _shape(_keyword(config_call, name) or ast.Constant(None)) != _shape(_expression(expected))
        for name, expected in expected_literals.items()
    ):
        violations.append(
            f"{path}:{per_server.lineno}: native MCP command, URL, headers, executable facts, "
            "type, name, and provenance must be copied literally"
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


def _check_local_bundle_boundary(tree: ast.Module, path: Path) -> list[str]:
    """Require legacy-only local bundle MCP parsing and wiring."""
    install = _find_function(tree, "install_local_bundle")
    parser = _find_function(tree, "_parse_legacy_bundle_mcp_servers")
    writer = _find_function(tree, "_wire_legacy_bundle_mcp_servers")
    format_guard = _find_function(tree, "_require_legacy_bundle_mcp_format")
    if install is None or parser is None or writer is None or format_guard is None:
        return [f"{path}: legacy local-bundle MCP helpers must each have one definition"]

    violations: list[str] = []
    is_agent_plugin_assignments = [
        node.value
        for node in ast.walk(install)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "is_agent_plugin"
    ]
    if len(is_agent_plugin_assignments) != 1 or _shape(is_agent_plugin_assignments[0]) != _shape(
        _expression('getattr(bundle_info, "format", "") == BundleFormat.AGENT_PLUGIN.value')
    ):
        violations.append(
            f"{path}:{install.lineno}: local-bundle native classification must use "
            "BundleFormat.AGENT_PLUGIN"
        )

    guard_raises = [
        node
        for node in ast.walk(format_guard)
        if isinstance(node, ast.Raise)
        and isinstance(node.exc, ast.Call)
        and _call_name(node.exc) == "AgentPluginLegacyBoundaryError"
    ]
    guard_tests = [
        node
        for node in ast.walk(format_guard)
        if isinstance(node, ast.Compare)
        and _shape(node) == _shape(_expression("bundle_format == BundleFormat.AGENT_PLUGIN.value"))
    ]
    legacy_allowlist_tests = [
        node
        for node in ast.walk(format_guard)
        if isinstance(node, ast.Compare)
        and _shape(node) == _shape(_expression("bundle_format != BundleFormat.CLAUDE_PLUGIN.value"))
    ]
    if len(guard_tests) != 1 or len(guard_raises) != 1 or len(legacy_allowlist_tests) != 1:
        violations.append(
            f"{path}:{format_guard.lineno}: legacy MCP helpers must reject "
            "BundleFormat.AGENT_PLUGIN and allow only BundleFormat.CLAUDE_PLUGIN"
        )

    removed_helpers = {
        "_parse_bundle_mcp_servers",
        "_wire_bundle_mcp_servers",
    }
    live_functions = {
        node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if live_functions & removed_helpers:
        violations.append(
            f"{path}: native-capable local-bundle MCP helper names must remain retired"
        )

    parser_args = {
        argument.arg
        for argument in (
            *parser.args.posonlyargs,
            *parser.args.args,
            *parser.args.kwonlyargs,
        )
    }
    if "agent_plugin" in parser_args:
        violations.append(
            f"{path}:{parser.lineno}: legacy MCP parser must not accept a native Agent Plugin mode"
        )
    for legacy_function in (parser, writer):
        first = _first_statement_after_docstring(legacy_function)
        if (
            not isinstance(first, ast.Expr)
            or not isinstance(first.value, ast.Call)
            or _call_name(first.value) != "_require_legacy_bundle_mcp_format"
            or len(first.value.args) != 1
            or not isinstance(first.value.args[0], ast.Name)
            or first.value.args[0].id != "bundle_format"
        ):
            violations.append(
                f"{path}:{legacy_function.lineno}: legacy MCP helper must reject native format "
                "before interpretation or writes"
            )

    parser_calls = {_call_name(node) for node in ast.walk(parser) if isinstance(node, ast.Call)}
    forbidden_parser_calls = sorted(
        parser_calls & {"load_agent_plugin", "validate_mcp_config_file"}
    )
    if forbidden_parser_calls:
        violations.append(
            f"{path}:{parser.lineno}: legacy MCP parser must not reinterpret native Agent Plugin "
            f"metadata: {', '.join(forbidden_parser_calls)}"
        )

    nested_helpers = {node.name for node in parser.body if isinstance(node, ast.FunctionDef)}
    expected_nested = {
        "_expand_legacy_placeholders",
        "_materialize_legacy_server_config",
    }
    if not expected_nested <= nested_helpers:
        violations.append(
            f"{path}:{parser.lineno}: legacy placeholder and materialization behavior must stay "
            "explicitly scoped beneath the legacy parser"
        )

    parents = _parent_fields(tree)
    legacy_calls = {
        "_parse_legacy_bundle_mcp_servers",
        "_wire_legacy_bundle_mcp_servers",
    }
    for reference in (
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in legacy_calls
    ):
        parent = parents.get(reference)
        call = parent[0] if parent is not None else None
        if not (
            isinstance(call, ast.Call)
            and call.func is reference
            and _enclosing_function(call, parents) is install
            and _is_legacy_guarded(call, install, parents)
        ):
            violations.append(
                f"{path}:{reference.lineno}: native Agent Plugin flow must not reach or alias "
                f"legacy MCP interpretation or writes via {reference.id}"
            )

    legacy_owner_calls = {
        "MCPDependency.from_dict": parser.name,
        "MCPIntegrator.install": writer.name,
        "run_owned_mcp_integration": writer.name,
        "validate_mcp_config_file": parser.name,
    }
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        call_name = _call_name(call)
        required_owner = legacy_owner_calls.get(call_name)
        owner = _enclosing_function(call, parents)
        if required_owner is not None and (owner is None or owner.name != required_owner):
            violations.append(
                f"{path}:{call.lineno}: {call_name} must remain inside the legacy-only "
                f"{required_owner} owner"
            )

    forbidden_anywhere = {
        "AuthResolver",
        "GitHubTokenManager",
        "os.environ.get",
        "os.getenv",
    }
    forbidden_calls = sorted(
        {
            _call_name(node)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and _call_name(node) in forbidden_anywhere
        }
    )
    forbidden_imports = sorted(
        {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
            if alias.name in {"AuthResolver", "GitHubTokenManager"}
        }
    )
    ambient_names = sorted(
        {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in _AMBIENT_CREDENTIAL_NAMES
        }
    )
    if forbidden_calls or forbidden_imports or ambient_names:
        details = sorted({*forbidden_calls, *forbidden_imports, *ambient_names})
        violations.append(
            f"{path}: local-bundle native MCP seam must not resolve or name ambient "
            f"credentials: {', '.join(details)}"
        )
    return violations


def _check_external_legacy_helper_references(root: Path) -> list[str]:
    """Reject legacy MCP helper call sites outside their owning module."""
    helper_names = {
        "_parse_legacy_bundle_mcp_servers",
        "_wire_legacy_bundle_mcp_servers",
    }
    violations: list[str] = []
    source_root = root / "src/apm_cli"
    for path in source_root.rglob("*.py"):
        relative = path.relative_to(root)
        if relative == LOCAL_BUNDLE_PATH:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(relative))
        except (OSError, SyntaxError) as exc:
            violations.append(f"{relative}: cannot inspect legacy MCP references: {exc}")
            continue
        references = sorted(
            {
                (node.lineno, node.id)
                for node in ast.walk(tree)
                if isinstance(node, ast.Name) and node.id in helper_names
            }
            | {
                (node.lineno, node.attr)
                for node in ast.walk(tree)
                if isinstance(node, ast.Attribute) and node.attr in helper_names
            }
            | {
                (node.lineno, alias.name)
                for node in ast.walk(tree)
                if isinstance(node, (ast.Import, ast.ImportFrom))
                for alias in node.names
                if alias.name in helper_names
            }
        )
        for lineno, name in references:
            violations.append(
                f"{relative}:{lineno}: {name} is legacy-only and must not gain external "
                "native Agent Plugin call sites"
            )
    return violations


def check(root: Path) -> list[str]:
    """Return native Agent Plugin MCP boundary violations."""
    paths = (
        FACADE_PATH,
        PROJECTOR_PATH,
        MODEL_PATH,
        LOCAL_BUNDLE_PATH,
    )
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
    violations.extend(_check_local_bundle_boundary(trees[LOCAL_BUNDLE_PATH], LOCAL_BUNDLE_PATH))
    violations.extend(_check_external_legacy_helper_references(root))
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
