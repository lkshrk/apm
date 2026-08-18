#!/usr/bin/env python3
"""Static boundary check for the canonical Agent Plugin component IR."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

_PORTABLE_FIELDS = ("skills", "mcp_servers")
_APM_DIRECTORY_COMPONENTS = ("agents", "commands", "instructions", "extensions")


def _module(root: Path, relative: str) -> tuple[str, ast.Module]:
    source = (root / relative).read_text(encoding="utf-8")
    return source, ast.parse(source)


def _class_fields(tree: ast.Module, name: str) -> tuple[str, ...]:
    class_node = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == name
    )
    return tuple(
        node.target.id
        for node in class_node.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    )


def _assigned_literal(tree: ast.Module, name: str) -> object:
    assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
    )
    return ast.literal_eval(assignment.value)


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    return next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name
    )


def _has_call(tree: ast.AST, owner: str, method: str) -> bool:
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == owner
        and node.func.attr == method
        for node in ast.walk(tree)
    )


def check(root: Path) -> list[str]:
    ir_source, ir_tree = _module(root, "src/apm_cli/agent_plugins/ir.py")
    loader_source, loader_tree = _module(root, "src/apm_cli/agent_plugins/loader.py")
    assets_source, assets_tree = _module(root, "src/apm_cli/agent_plugins/assets.py")
    _projection_source, projection_tree = _module(
        root,
        "src/apm_cli/agent_plugins/projection.py",
    )
    failures: list[str] = []

    if _class_fields(ir_tree, "AgentPluginComponents") != _PORTABLE_FIELDS:
        failures.append("portable AgentPluginComponents fields changed")
    if _assigned_literal(loader_tree, "_APM_DIRECTORY_COMPONENTS") != _APM_DIRECTORY_COMPONENTS:
        failures.append("APM extension directory vocabulary changed")
    if _class_fields(ir_tree, "AgentPluginAsset") != (
        "path",
        "source",
        "sha256",
        "size",
        "executable_mode",
    ):
        failures.append("asset integrity facts changed")
    if "apm_components: ApmExtensionComponents | None" not in ir_source:
        failures.append("AgentPlugin lost its optional APM component aggregate")
    if "if extension is None or extension.schema_version !=" not in loader_source:
        failures.append("undeclared APM extension activation guard changed")
    if "if stat.S_ISLNK" not in assets_source or not _has_call(
        assets_tree,
        "hashlib",
        "sha256",
    ):
        failures.append("asset symlink or digest enforcement changed")
    if "ensure_path_within" not in assets_source:
        failures.append("asset containment enforcement changed")
    for name in ("_discover_apm_lsp_component", "_discover_apm_hook_component"):
        if any(isinstance(node, ast.Raise) for node in ast.walk(_function(loader_tree, name))):
            failures.append(f"{name} may abort unrelated components")
    forbidden_scan_methods = {"glob", "iterdir", "read_bytes", "read_text", "rglob"}
    if any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in forbidden_scan_methods
        for node in ast.walk(projection_tree)
    ):
        failures.append("projection rescans source files instead of consuming IR")
    if '"bin"' in ast.get_source_segment(loader_source, _function(loader_tree, "_load_v1")) or (
        "bin" in _assigned_literal(loader_tree, "_APM_DIRECTORY_COMPONENTS")
    ):
        failures.append("root bin was promoted to a component")
    return failures


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).parents[1]
    failures = check(root)
    for failure in failures:
        print(f"[x] {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
