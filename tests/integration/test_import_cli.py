from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from apm_cli.cli import cli
from apm_cli.importing import ImportProtocolError, ImportService


def test_import_envelope_goldens_validate_against_packaged_schema():
    root = Path(__file__).parents[2]
    schema_root = root / "src" / "apm_cli" / "schemas"
    schemas = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in schema_root.glob("import-*-v1.json")
    ]
    registry = Registry().with_resources(
        [(schema["$id"], Resource.from_contents(schema)) for schema in schemas]
    )
    envelope_schema = next(
        schema for schema in schemas if schema["$id"].endswith("import-envelope-v1.json")
    )
    validator = Draft202012Validator(envelope_schema, registry=registry)
    goldens = json.loads(
        (root / "tests" / "fixtures" / "import_protocol" / "envelopes-v1.json").read_text(
            encoding="utf-8"
        )
    )
    for envelope in goldens.values():
        validator.validate(envelope)


def test_real_cli_scan_apply_status_and_finalize(monkeypatch, tmp_path):
    home = tmp_path / "home"
    skill = home / ".agents" / "skills" / "demo"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    second_skill = home / ".agents" / "skills" / "second"
    second_skill.mkdir(parents=True)
    (second_skill / "SKILL.md").write_text("# Second\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APM_E2E_TESTS", "1")
    candidates = tmp_path / "candidates.json"
    plan = tmp_path / "plan.json"
    runner = CliRunner()
    scan = runner.invoke(
        cli,
        [
            "import",
            "--global",
            "--from",
            "codex",
            "--candidate-file",
            str(candidates),
            "--plan-json",
            str(plan),
            "--coordinator",
            "omni-v24",
            "--format",
            "json",
        ],
    )
    assert scan.exit_code == 0, scan.output
    assert not (home / ".apm").exists()
    scan_envelope = json.loads(scan.stdout)
    assert scan_envelope["ok"] is True
    assert scan_envelope["kind"] == "import-plan"
    operation = scan_envelope["plan"]["operation_id"]
    token = "x" * 44
    apply = runner.invoke(
        cli,
        [
            "import",
            "--global",
            "--candidate-file",
            str(candidates),
            "--apply-plan",
            str(plan),
            "--coordinator",
            "omni-v24",
            "--omni-preimage-set",
            "v24-hash",
            "--token-stdin",
            "--format",
            "json",
        ],
        input=token,
    )
    assert apply.exit_code == 0, apply.output
    apply_envelope = json.loads(apply.stdout)
    assert apply_envelope["ok"] is True
    assert apply_envelope["kind"] == "import-apply-result"
    assert apply_envelope["result"]["state"] == "awaiting-external-commit"
    status = runner.invoke(cli, ["import", "status", "--operation", operation, "--format", "json"])
    assert status.exit_code == 0, status.output
    status_envelope = json.loads(status.stdout)
    assert status_envelope["ok"] is True
    assert status_envelope["kind"] == "import-status-result"
    assert status_envelope["result"]["finalize_token_required"] is True
    finalize = runner.invoke(
        cli,
        [
            "import",
            "finalize",
            "--operation",
            operation,
            "--omni-preimage-set",
            "v24-hash",
            "--token-stdin",
            "--format",
            "json",
        ],
        input=token,
    )
    assert finalize.exit_code == 0, finalize.output
    finalize_envelope = json.loads(finalize.stdout)
    assert finalize_envelope["ok"] is True
    assert finalize_envelope["kind"] == "import-finalize-result"
    assert finalize_envelope["result"]["state"] == "complete"


def test_import_protocol_error_has_stable_typed_envelope(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APM_E2E_TESTS", "1")
    result = CliRunner().invoke(
        cli,
        ["import", "status", "--operation", "../escape", "--format", "json"],
    )
    assert result.exit_code == 5
    assert json.loads(result.stdout) == {
        "ok": False,
        "kind": "import-error",
        "error": {
            "code": "protocol-incompatible",
            "message": "operation ID must be exactly 32 lowercase hexadecimal characters",
        },
    }
    assert not (home / ".apm").exists()


def test_import_error_envelope_redacts_secret_patterns(monkeypatch):
    monkeypatch.setattr(
        ImportService,
        "status",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ImportProtocolError("token=supersecretvalue")
        ),
    )
    result = CliRunner().invoke(
        cli,
        ["import", "status", "--operation", "a" * 32, "--format", "json"],
    )
    assert result.exit_code == 5
    envelope = json.loads(result.stdout)
    assert envelope == {
        "ok": False,
        "kind": "import-error",
        "error": {
            "code": "protocol-incompatible",
            "message": "[REDACTED]",
            "operation_id": "a" * 32,
        },
    }
    assert "supersecretvalue" not in result.output


@pytest.mark.parametrize(
    ("method", "argv", "kind", "input_text"),
    [
        ("status", ["status", "--operation", "a" * 32], "import-status-result", None),
        ("rollback", ["rollback", "--operation", "a" * 32], "import-rollback-result", None),
        (
            "cleanup",
            ["cleanup", "--operation", "a" * 32, "--confirm"],
            "import-cleanup-result",
            None,
        ),
        (
            "finalize",
            [
                "finalize",
                "--operation",
                "a" * 32,
                "--omni-preimage-set",
                "hash",
                "--token-stdin",
            ],
            "import-finalize-result",
            "x" * 44,
        ),
    ],
)
def test_recovery_commands_use_stable_result_kinds(monkeypatch, method, argv, kind, input_text):
    payload = {
        "schema_version": 1,
        "operation_id": "a" * 32,
        "coordinator": "standalone",
        "state": "complete",
        "next_action": "none",
        "finalize_token_required": False,
    }
    monkeypatch.setattr(ImportService, method, lambda *_args, **_kwargs: payload)
    result = CliRunner().invoke(
        cli,
        ["import", *argv, "--format", "json"],
        input=input_text,
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"ok": True, "kind": kind, "result": payload}


def test_resume_uses_stable_result_kind(monkeypatch, tmp_path):
    payload = {
        "schema_version": 1,
        "operation_id": "a" * 32,
        "coordinator": "standalone",
        "state": "complete",
        "next_action": "none",
        "finalize_token_required": False,
    }
    monkeypatch.setattr(ImportService, "resume", lambda *_args, **_kwargs: payload)
    result = CliRunner().invoke(
        cli,
        [
            "import",
            "resume",
            "--operation",
            "a" * 32,
            "--candidate-file",
            str(tmp_path / "candidates.json"),
            "--apply-plan",
            str(tmp_path / "plan.json"),
            "--coordinator",
            "standalone",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "ok": True,
        "kind": "import-resume-result",
        "result": payload,
    }


def test_real_subprocess_same_operation_apply_and_resume_lock(monkeypatch, tmp_path):
    home = tmp_path / "home"
    skill = home / ".agents" / "skills" / "locked"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# Locked\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APM_E2E_TESTS", "1")
    candidates = tmp_path / "candidates.json"
    plan = tmp_path / "plan.json"
    scan = CliRunner().invoke(
        cli,
        [
            "import",
            "--global",
            "--from",
            "codex",
            "--candidate-file",
            str(candidates),
            "--plan-json",
            str(plan),
            "--format",
            "json",
        ],
    )
    assert scan.exit_code == 0, scan.output
    operation = json.loads(scan.stdout)["plan"]["operation_id"]
    apm = str(Path(sys.executable).with_name("apm.exe" if os.name == "nt" else "apm"))
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home), "APM_E2E_TESTS": "1"}
    apply_argv = [
        apm,
        "import",
        "--global",
        "--candidate-file",
        str(candidates),
        "--apply-plan",
        str(plan),
        "--format",
        "json",
    ]
    apply_processes = [
        subprocess.Popen(
            apply_argv, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        for _ in range(2)
    ]
    for process in apply_processes:
        stdout, stderr = process.communicate(timeout=60)
        assert process.returncode == 0, stderr or stdout
        assert json.loads(stdout)["result"]["state"] == "complete"

    resume_argv = [
        apm,
        "import",
        "resume",
        "--operation",
        operation,
        "--candidate-file",
        str(candidates),
        "--apply-plan",
        str(plan),
        "--coordinator",
        "standalone",
        "--format",
        "json",
    ]
    resume_processes = [
        subprocess.Popen(
            resume_argv, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        for _ in range(2)
    ]
    for process in resume_processes:
        stdout, stderr = process.communicate(timeout=60)
        assert process.returncode == 0, stderr or stdout
        assert json.loads(stdout)["result"]["state"] == "complete"
