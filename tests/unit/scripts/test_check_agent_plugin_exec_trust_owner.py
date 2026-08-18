"""Mutation guards for the Agent Plugin executable-trust owner."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path
from types import ModuleType


def _checker() -> ModuleType:
    root = Path(__file__).parents[3]
    path = root / "scripts" / "check_agent_plugin_exec_trust_owner.py"
    spec = importlib.util.spec_from_file_location("check_agent_plugin_exec_trust_owner", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _contract_root(tmp_path: Path) -> Path:
    repository = Path(__file__).parents[3]
    for relative in (
        Path("src/apm_cli/security/executables.py"),
        Path("src/apm_cli/install/exec_gate.py"),
    ):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repository / relative, destination)
    return tmp_path


def _messages(root: Path) -> list[str]:
    return [violation.message for violation in _checker().check_root(root)]


def test_repository_satisfies_exec_trust_owner_contract() -> None:
    root = Path(__file__).parents[3]
    assert _checker().check_root(root) == []


def test_duplicate_context_assembly_is_rejected(tmp_path: Path) -> None:
    root = _contract_root(tmp_path)
    rogue = root / "src/apm_cli/install/rogue.py"
    rogue.write_text("value = ExecTrustDecisionContext(policy, source, component, False)\n")

    assert any("construction belongs" in message for message in _messages(root))


def test_integrator_cannot_call_decision_or_gate_directly(tmp_path: Path) -> None:
    root = _contract_root(tmp_path)
    rogue = root / "src/apm_cli/integration/rogue.py"
    rogue.parent.mkdir(parents=True)
    rogue.write_text(
        "resolve_agent_plugin_exec_decision(context)\n"
        "evaluate_agent_plugin_executable_trust(plugin, trust_context=policy, source_facts=source)\n"
    )

    messages = _messages(root)
    assert any("must be consumed through" in message for message in messages)
    assert any("cannot bypass" in message for message in messages)


def test_duplicate_exec_gate_facade_is_rejected(tmp_path: Path) -> None:
    root = _contract_root(tmp_path)
    gate = root / "src/apm_cli/install/exec_gate.py"
    with gate.open("a", encoding="utf-8") as handle:
        handle.write(
            "\ndef bypass(context):\n"
            "    assembled = assemble_agent_plugin_exec_trust_context(context)\n"
            "    return resolve_agent_plugin_exec_decision(assembled)\n"
        )

    assert any("cannot be called outside" in message for message in _messages(root))


def test_ingress_derived_source_fact_is_rejected(tmp_path: Path) -> None:
    root = _contract_root(tmp_path)
    owner = root / "src/apm_cli/security/executables.py"
    text = owner.read_text()
    owner.write_text(
        text.replace(
            "    signature_verified: bool | None = None\n",
            "    signature_verified: bool | None = None\n    ingress_kind: str | None = None\n",
        )
    )

    assert any("cannot carry ingress kind" in message for message in _messages(root))


def test_missing_component_identity_validation_is_rejected(tmp_path: Path) -> None:
    root = _contract_root(tmp_path)
    owner = root / "src/apm_cli/security/executables.py"
    text = owner.read_text()
    owner.write_text(text.replace("        or not component.name\n", "        or False\n", 1))

    assert any("component validation is missing" in message for message in _messages(root))


def test_missing_plugin_name_validation_is_rejected(tmp_path: Path) -> None:
    root = _contract_root(tmp_path)
    owner = root / "src/apm_cli/security/executables.py"
    text = owner.read_text()
    owner.write_text(text.replace("        not context.plugin_name\n", "        False\n", 1))

    assert any("trust-context validation is missing" in message for message in _messages(root))


def test_missing_content_digest_validation_is_rejected(tmp_path: Path) -> None:
    root = _contract_root(tmp_path)
    owner = root / "src/apm_cli/security/executables.py"
    text = owner.read_text()
    owner.write_text(
        text.replace(
            "for value in (source.resolved_revision, source.content_digest):",
            "for value in (source.resolved_revision,):",
            1,
        )
    )

    assert any("source-fact validation is missing" in message for message in _messages(root))


def test_implicit_gate_disabled_approval_mutation_is_rejected(tmp_path: Path) -> None:
    root = _contract_root(tmp_path)
    owner = root / "src/apm_cli/security/executables.py"
    text = owner.read_text()
    owner.write_text(
        text.replace(
            "    if decision.deciding_layer == LAYER_GATE_DISABLED:\n",
            "    if False:\n",
            1,
        )
    )

    assert any("default deny" in message for message in _messages(root))
