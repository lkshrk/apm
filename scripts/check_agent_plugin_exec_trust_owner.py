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
}
REQUIRED_CONTEXT_VALIDATION = {"plugin_name", "plugin_version", "explicit_consent"}
REQUIRED_SOURCE_VALIDATION = EXPECTED_SOURCE_FIELDS


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
