#!/usr/bin/env python3
"""Enforce one Agent Plugin executable-trust assembly and decision owner."""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
from pathlib import Path

OWNER_PATH = Path("src/apm_cli/security/executables.py")
GATE_PATH = Path("src/apm_cli/install/exec_gate.py")
CONTEXT_TYPE = "ExecTrustDecisionContext"
ASSEMBLY_OWNER = "assemble_agent_plugin_exec_trust_context"
DECISION_OWNER = "resolve_agent_plugin_exec_decision"
GATE_OWNER = "evaluate_agent_plugin_executable_trust"
REQUIRED_OWNER_SYMBOLS = {
    CONTEXT_TYPE,
    ASSEMBLY_OWNER,
    DECISION_OWNER,
    "inventory_agent_plugin_executables",
}
DIRECT_OWNER_CALLS = {ASSEMBLY_OWNER, DECISION_OWNER}
EXPECTED_CONTEXT_FIELDS = {
    "policy",
    "source",
    "plugin_name",
    "plugin_version",
    "component",
    "explicit_consent",
}
EXPECTED_SOURCE_FIELDS = {
    "canonical_source",
    "resolved_revision",
    "content_digest",
    "integrity_verified",
    "signature_verified",
}
REQUIRED_COMPONENT_VALIDATION = {
    "plugin_key",
    "kind",
    "name",
    "classification",
    "exec_type",
    "command",
    "args",
    "cwd",
    "provenance",
    "declaration",
}
REQUIRED_ASSET_VALIDATION = {
    "asset_state",
    "plugin_relative_path",
    "asset_sha256",
    "asset_size",
    "asset_executable_mode",
}
REQUIRED_CONTEXT_VALIDATION = {"plugin_name", "plugin_version", "explicit_consent"}
REQUIRED_SOURCE_VALIDATION = EXPECTED_SOURCE_FIELDS
INVENTORY_FUNCTIONS = {
    "inventory_agent_plugin_executables",
    "_canonical_provenance",
    "_asset_classification",
    "_asset_component",
    "_declared_executable_component",
    "_append_declared_executables",
    "_append_file_component_assets",
    "_append_unreferenced_assets",
}
FORBIDDEN_INVENTORY_CALLS = {
    "glob",
    "iterdir",
    "load_agent_plugin",
    "loads",
    "open",
    "open_verified_asset",
    "parse",
    "read_bytes",
    "read_text",
    "rglob",
    "walk",
}


@dataclass(frozen=True, slots=True)
class Violation:
    """One executable-trust architecture violation."""

    path: Path
    line: int
    message: str

    def render(self) -> str:
        """Return one actionable diagnostic."""
        return f"{self.path}:{self.line}: {self.message}"


def _definitions(tree: ast.Module) -> set[str]:
    """Return top-level class and function names."""
    return {
        node.name
        for node in tree.body
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    }


def _definition(tree: ast.Module, name: str) -> ast.AST | None:
    """Return one top-level class or function definition."""
    return next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
            and node.name == name
        ),
        None,
    )


def _annotated_fields(node: ast.AST | None) -> set[str]:
    """Return annotated class field names."""
    if not isinstance(node, ast.ClassDef):
        return set()
    return {
        child.target.id
        for child in node.body
        if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name)
    }


def _condition_attributes(node: ast.AST | None, owner: str) -> set[str]:
    """Return attributes used in conditional expressions for a named local."""
    if node is None:
        return set()
    return {
        child.attr
        for condition in ast.walk(node)
        if isinstance(condition, ast.If)
        for child in ast.walk(condition.test)
        if isinstance(child, ast.Attribute)
        and isinstance(child.value, ast.Name)
        and child.value.id == owner
        and isinstance(child.ctx, ast.Load)
    }


def _loaded_attributes(node: ast.AST | None, owner: str) -> set[str]:
    """Return attributes loaded from a named local anywhere in a function."""
    if node is None:
        return set()
    return {
        child.attr
        for child in ast.walk(node)
        if isinstance(child, ast.Attribute)
        and isinstance(child.value, ast.Name)
        and child.value.id == owner
        and isinstance(child.ctx, ast.Load)
    }


def _call_name(call: ast.Call) -> str | None:
    """Return the terminal name of a direct or attribute call."""
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _none_comparison_signatures(node: ast.AST | None) -> set[frozenset[tuple[str, str]]]:
    """Return name/None comparisons grouped by each conditional expression."""
    if node is None:
        return set()
    signatures: set[frozenset[tuple[str, str]]] = set()
    for condition in ast.walk(node):
        if not isinstance(condition, ast.If):
            continue
        comparisons: set[tuple[str, str]] = set()
        for child in ast.walk(condition.test):
            if (
                isinstance(child, ast.Compare)
                and isinstance(child.left, ast.Name)
                and len(child.ops) == 1
                and len(child.comparators) == 1
                and isinstance(child.comparators[0], ast.Constant)
                and child.comparators[0].value is None
                and isinstance(child.ops[0], ast.Is | ast.IsNot)
            ):
                comparisons.add((child.left.id, type(child.ops[0]).__name__))
        if comparisons:
            signatures.add(frozenset(comparisons))
    return signatures


def _assigns_attribute(
    node: ast.AST | None,
    *,
    target_name: str,
    owner_name: str,
    attribute_name: str,
) -> bool:
    """Return whether a local is assigned from the required canonical fact."""
    if node is None:
        return False
    return any(
        isinstance(child, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == target_name for target in child.targets
        )
        and isinstance(child.value, ast.Attribute)
        and isinstance(child.value.value, ast.Name)
        and child.value.value.id == owner_name
        and child.value.attr == attribute_name
        for child in ast.walk(node)
    )


def _has_name_attribute_comparison(
    node: ast.AST | None,
    *,
    name: str,
    operator: type[ast.cmpop],
    owner: str,
    attribute: str,
) -> bool:
    """Return whether a conditional binds a local to a canonical attribute."""
    if node is None:
        return False
    for child in ast.walk(node):
        if (
            not isinstance(child, ast.Compare)
            or len(child.ops) != 1
            or not isinstance(child.ops[0], operator)
            or len(child.comparators) != 1
        ):
            continue
        pairs = (
            (child.left, child.comparators[0]),
            (child.comparators[0], child.left),
        )
        if any(
            isinstance(local, ast.Name)
            and local.id == name
            and isinstance(fact, ast.Attribute)
            and isinstance(fact.value, ast.Name)
            and fact.value.id == owner
            and fact.attr == attribute
            for local, fact in pairs
        ):
            return True
    return False


def check_root(root: Path) -> list[Violation]:
    """Return trust-owner violations under *root*."""
    violations: list[Violation] = []
    owner = root / OWNER_PATH
    gate = root / GATE_PATH
    if not owner.is_file():
        return [Violation(OWNER_PATH, 1, "canonical executable-trust owner is missing")]
    if not gate.is_file():
        return [Violation(GATE_PATH, 1, "install executable-trust gate is missing")]

    owner_tree = ast.parse(owner.read_text(encoding="utf-8"), filename=str(OWNER_PATH))
    missing = sorted(REQUIRED_OWNER_SYMBOLS - _definitions(owner_tree))
    for symbol in missing:
        violations.append(Violation(OWNER_PATH, 1, f"canonical owner symbol is missing: {symbol}"))

    owner_context_calls = [
        node
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Call) and _call_name(node) == CONTEXT_TYPE
    ]
    if len(owner_context_calls) != 1:
        violations.append(
            Violation(
                OWNER_PATH,
                1,
                f"{CONTEXT_TYPE} must be assembled exactly once by {ASSEMBLY_OWNER}",
            )
        )

    context_fields = _annotated_fields(_definition(owner_tree, CONTEXT_TYPE))
    if context_fields != EXPECTED_CONTEXT_FIELDS:
        violations.append(
            Violation(
                OWNER_PATH,
                1,
                f"{CONTEXT_TYPE} fields must be canonical policy/source/component/consent facts",
            )
        )
    source_fields = _annotated_fields(_definition(owner_tree, "ExecSourceFacts"))
    if source_fields != EXPECTED_SOURCE_FIELDS:
        violations.append(
            Violation(
                OWNER_PATH,
                1,
                "ExecSourceFacts cannot carry ingress kind, cache path, or source basename trust",
            )
        )
    validator = _definition(owner_tree, "_validate_exec_decision_context")
    component_fields = _condition_attributes(validator, "component")
    missing_component_fields = sorted(REQUIRED_COMPONENT_VALIDATION - component_fields)
    if missing_component_fields:
        violations.append(
            Violation(
                OWNER_PATH,
                getattr(validator, "lineno", 1),
                "component validation is missing: " + ", ".join(missing_component_fields),
            )
        )
    context_fields = _condition_attributes(validator, "context")
    missing_context_fields = sorted(REQUIRED_CONTEXT_VALIDATION - context_fields)
    if missing_context_fields:
        violations.append(
            Violation(
                OWNER_PATH,
                getattr(validator, "lineno", 1),
                "trust-context validation is missing: " + ", ".join(missing_context_fields),
            )
        )
    source_validation = _loaded_attributes(validator, "source")
    missing_source_fields = sorted(REQUIRED_SOURCE_VALIDATION - source_validation)
    if missing_source_fields:
        violations.append(
            Violation(
                OWNER_PATH,
                getattr(validator, "lineno", 1),
                "source-fact validation is missing: " + ", ".join(missing_source_fields),
            )
        )
    asset_validator = _definition(owner_tree, "_validate_executable_asset_facts")
    asset_validation = _loaded_attributes(asset_validator, "component")
    missing_asset_fields = sorted(REQUIRED_ASSET_VALIDATION - asset_validation)
    if missing_asset_fields or not _assigns_attribute(
        asset_validator,
        target_name="digest",
        owner_name="component",
        attribute_name="asset_sha256",
    ):
        violations.append(
            Violation(
                OWNER_PATH,
                getattr(asset_validator, "lineno", 1),
                "executable asset validation is missing"
                + (": " + ", ".join(missing_asset_fields) if missing_asset_fields else ""),
            )
        )
    asset_validator_names = {
        child.id
        for child in ast.walk(asset_validator)
        if asset_validator is not None
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
    }
    required_asset_fail_closed_names = {
        "ASSET_STATE_EXTERNAL",
        "ASSET_STATE_MISSING",
        "ASSET_STATE_VERIFIED",
        "FAILURE_MISSING_ASSET",
    }
    if not required_asset_fail_closed_names <= asset_validator_names:
        violations.append(
            Violation(
                OWNER_PATH,
                getattr(asset_validator, "lineno", 1),
                "asset validation must fail closed for external, missing, and verified states",
            )
        )
    state_owner = _definition(owner_tree, "_declared_executable_component")
    required_state_signatures = {
        frozenset({("relative", "Is"), ("asset", "Is")}),
        frozenset({("relative", "IsNot"), ("asset", "Is")}),
        frozenset({("relative", "IsNot"), ("asset", "IsNot")}),
    }
    if not required_state_signatures <= _none_comparison_signatures(state_owner):
        violations.append(
            Violation(
                OWNER_PATH,
                getattr(state_owner, "lineno", 1),
                "canonical executable states must distinguish external, missing, and verified assets",
            )
        )
    if not _has_name_attribute_comparison(
        state_owner,
        name="relative",
        operator=ast.Eq,
        owner="asset",
        attribute="path",
    ):
        violations.append(
            Violation(
                OWNER_PATH,
                getattr(state_owner, "lineno", 1),
                "verified executable assets must bind their canonical path facts",
            )
        )
    for function_name in sorted(INVENTORY_FUNCTIONS):
        definition = _definition(owner_tree, function_name)
        if definition is None:
            violations.append(
                Violation(OWNER_PATH, 1, f"canonical inventory helper is missing: {function_name}")
            )
            continue
        forbidden = sorted(
            {
                name
                for child in ast.walk(definition)
                if isinstance(child, ast.Call)
                and (name := _call_name(child)) in FORBIDDEN_INVENTORY_CALLS
            }
        )
        if forbidden:
            violations.append(
                Violation(
                    OWNER_PATH,
                    getattr(definition, "lineno", 1),
                    "canonical executable inventory cannot rediscover, reparse, or reopen files: "
                    + ", ".join(forbidden),
                )
            )
    resolver = _definition(owner_tree, DECISION_OWNER)
    resolver_names = {
        child.id
        for child in ast.walk(resolver)
        if resolver is not None
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
    }
    required_fail_closed_names = {
        "LAYER_GATE_DISABLED",
        "LAYER_DEFAULT_DENY",
        "LAYER_EXPLICIT_CONSENT",
    }
    if not required_fail_closed_names <= resolver_names:
        violations.append(
            Violation(
                OWNER_PATH,
                getattr(resolver, "lineno", 1),
                "Agent Plugin decisions must default deny and scope explicit consent",
            )
        )

    source_root = root / "src" / "apm_cli"
    for path in sorted(source_root.rglob("*.py")):
        relative = path.relative_to(root)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(relative))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name == CONTEXT_TYPE and relative != OWNER_PATH:
                violations.append(
                    Violation(
                        relative,
                        node.lineno,
                        f"{CONTEXT_TYPE} construction belongs to {OWNER_PATH}",
                    )
                )
            if name in DIRECT_OWNER_CALLS and relative not in {OWNER_PATH, GATE_PATH}:
                violations.append(
                    Violation(
                        relative,
                        node.lineno,
                        f"{name} must be consumed through {GATE_PATH}:{GATE_OWNER}",
                    )
                )
            if name == GATE_OWNER and relative.parts[:3] == ("src", "apm_cli", "integration"):
                violations.append(
                    Violation(
                        relative,
                        node.lineno,
                        "integrators cannot bypass the install executable-trust gate",
                    )
                )

    gate_tree = ast.parse(gate.read_text(encoding="utf-8"), filename=str(GATE_PATH))
    gate_defs = _definitions(gate_tree)
    if GATE_OWNER not in gate_defs:
        violations.append(Violation(GATE_PATH, 1, f"integration seam is missing: {GATE_OWNER}"))
    gate_owner = _definition(gate_tree, GATE_OWNER)
    gate_calls = [
        name
        for node in (ast.walk(gate_owner) if gate_owner is not None else ())
        if isinstance(node, ast.Call) and (name := _call_name(node)) in DIRECT_OWNER_CALLS
    ]
    if {name: gate_calls.count(name) for name in DIRECT_OWNER_CALLS} != {
        name: 1 for name in DIRECT_OWNER_CALLS
    }:
        violations.append(
            Violation(
                GATE_PATH,
                1,
                f"{GATE_OWNER} must call each canonical assembly and decision owner exactly once",
            )
        )
    for definition in gate_tree.body:
        if not isinstance(definition, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if definition.name == GATE_OWNER:
            continue
        for node in ast.walk(definition):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name in DIRECT_OWNER_CALLS:
                violations.append(
                    Violation(
                        GATE_PATH,
                        node.lineno,
                        f"{name} cannot be called outside {GATE_OWNER}",
                    )
                )
    return violations


def main() -> int:
    """Run the checker from the command line."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    violations = check_root(args.root.resolve())
    for violation in violations:
        print(violation.render())
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
