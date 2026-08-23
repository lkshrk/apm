import json
from types import SimpleNamespace

import pytest

from apm_cli.integration.instruction_integrator import InstructionIntegrator


def test_imported_native_instruction_bypasses_converter_and_is_target_scoped(monkeypatch, tmp_path):
    package = tmp_path / "package"
    source = package / ".apm/native/instructions/claude/rules/raw.md"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"first\r\nlast")
    (package / ".apm-import.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "instruction",
                "layout": "compiled-instruction",
                "target": "claude",
                "targets": ["claude"],
                "format_id": "claude_rules",
                "relative_path": "rules/raw.md",
            }
        )
    )
    mapping = SimpleNamespace(
        deploy_root=None,
        subdir="rules",
        extension=".md",
        format_id="claude_rules",
        output_compare=True,
    )
    target = SimpleNamespace(
        name="claude",
        primitives={"instructions": mapping},
        root_dir=".claude",
        auto_create=True,
    )
    integrator = InstructionIntegrator()
    monkeypatch.setattr(
        integrator,
        "_render_instruction",
        lambda *_args, **_kwargs: pytest.fail("compiled bytes entered canonical converter"),
    )

    result = integrator.integrate_instructions_for_target(
        target,
        SimpleNamespace(install_path=package),
        tmp_path,
    )

    assert result.files_integrated == 1
    assert (tmp_path / ".claude/rules/raw.md").read_bytes() == b"first\r\nlast"
    assert not (tmp_path / ".codex").exists()
