"""Architecture regression for cross-process lifecycle serialization."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.architecture_linter.runner import run_selected_rules

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[2]
_RULE_ID = "install-deployment-lifecycle-serialization"
_CONFIG_PATH = "src/apm_cli/commands/config.py"


def test_lifecycle_mutators_route_through_canonical_lock() -> None:
    """The registered lifecycle boundary must remain clean."""
    result = run_selected_rules(_ROOT, {_RULE_ID})
    assert result.failures == ()
    assert result.violations == ()


def test_lifecycle_guard_rejects_unserialized_mutator() -> None:
    """The static guard rejects removal of a lifecycle-lock route."""
    source = (_ROOT / _CONFIG_PATH).read_text(encoding="utf-8")
    mutated = source.replace("@serialized_lifecycle\ndef set(", "def set(", 1)
    assert mutated != source

    result = run_selected_rules(
        _ROOT,
        {_RULE_ID},
        source_overrides={_CONFIG_PATH: mutated},
    )

    assert any(
        violation.rule_id == _RULE_ID and "set must route" in violation.message
        for violation in result.violations
    )
