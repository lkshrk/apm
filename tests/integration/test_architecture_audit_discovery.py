"""Audit consumers must not rederive primitive discovery or content applicability."""

from pathlib import Path

import pytest

from scripts.architecture_linter.runner import run_selected_rules

pytestmark = pytest.mark.component

_ROOT = Path(__file__).resolve().parents[2]
_RULE = "audit-primitive-discovery"
_SCANNER = "src/apm_cli/security/file_scanner.py"


def test_audit_discovery_uses_canonical_contract() -> None:
    result = run_selected_rules(_ROOT, {_RULE})
    assert result.failures == ()
    assert result.violations == ()


@pytest.mark.parametrize(
    "old,new",
    [
        (
            "for surface in primitive_surfaces(project_root, scoped, user_scope=user_scope):",
            "for surface in ():",
        ),
        ("return inspect_native_hooks(", "return bypass_native_hooks("),
        ("if not safe_surface_path(surface, path):", "if False:"),
    ],
)
def test_guard_rejects_discovery_applicability_or_containment_bypass(old: str, new: str) -> None:
    source = (_ROOT / _SCANNER).read_text(encoding="utf-8")
    mutated = source.replace(old, new, 1)
    assert mutated != source
    result = run_selected_rules(_ROOT, {_RULE}, source_overrides={_SCANNER: mutated})
    assert result.failures == ()
    assert any(v.rule_id == _RULE and v.path == _SCANNER for v in result.violations)
