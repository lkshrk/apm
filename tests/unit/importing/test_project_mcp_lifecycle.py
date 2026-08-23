from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner
from jsonschema import Draft202012Validator

from apm_cli.cli import cli
from apm_cli.importing import ImportProtocolError, ImportService, service
from apm_cli.importing.journal import read_journal


def _home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APM_E2E_TESTS", "1")
    return home


def _workspace(tmp_path: Path, name: str, server: str) -> Path:
    root = tmp_path / name
    config = root / ".vscode" / "mcp.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "servers": {
                    server: {
                        "type": "stdio",
                        "command": "python",
                        "args": ["-m", server],
                    }
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return root


def _scan(tmp_path: Path, root: Path, suffix: str = "") -> tuple[Path, Path, dict]:
    protocol = tmp_path / f"protocol{suffix}"
    candidate = protocol / "candidates.json"
    plan = protocol / "plan.json"
    result = ImportService().scan(
        sources=("vscode",),
        candidate_file=candidate,
        plan_json=plan,
        coordinator="standalone",
        project_root=root,
    )
    return candidate, plan, result


def _apply(root: Path, candidate: Path, plan: Path) -> dict:
    return ImportService().apply(
        candidate_file=candidate,
        plan_file=plan,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
        project_root=root,
    )


def _apply_from_reviewed_plan(candidate: Path, plan: Path) -> dict:
    return ImportService().apply(
        candidate_file=candidate,
        plan_file=plan,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )


def test_project_mcp_full_lifecycle_audit_and_second_scan(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    root = _workspace(tmp_path, "workspace", "demo")
    candidate, plan_file, plan = _scan(tmp_path, root)

    assert (plan["scope"], plan["project_root"]) == ("project", str(root))
    schema_root = Path(__file__).parents[3] / "src" / "apm_cli" / "schemas"
    Draft202012Validator(
        json.loads((schema_root / "import-candidates-v1.json").read_text())
    ).validate(json.loads(candidate.read_text()))
    Draft202012Validator(json.loads((schema_root / "import-plan-v1.json").read_text())).validate(
        plan
    )
    assert _apply_from_reviewed_plan(candidate, plan_file)["state"] == "complete"
    assert (root / "apm.yml").is_file()
    assert (root / "apm.lock.yaml").is_file()
    assert "demo" in json.loads((root / ".vscode" / "mcp.json").read_text())["servers"]
    assert not (home / ".apm" / "apm.yml").exists()
    assert not (home / ".apm" / "imported").exists()
    assert not (home / ".vscode").exists()

    journal = read_journal(plan["operation_id"])
    assert journal is not None
    assert (journal["scope"], journal["project_root"], journal["phase"]) == (
        "project",
        str(root),
        "audited",
    )
    second = _scan(tmp_path, root, "-second")[2]
    assert [(item["name"], item["classification"]) for item in second["items"]] == [
        ("demo", "already-managed")
    ]
    assert ImportService().cleanup(plan["operation_id"])["state"] == "complete"
    assert read_journal(plan["operation_id"])["cleaned"] is True


def test_project_mcp_rejects_mixed_missing_and_mismatched_roots_prewrite(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    first = _workspace(tmp_path, "first", "one")
    second = _workspace(tmp_path, "second", "two")
    candidate, plan_file, _ = _scan(tmp_path, first)

    with pytest.raises(ImportProtocolError, match="scope/project root mismatch"):
        _apply(second, candidate, plan_file)
    assert not (second / "apm.yml").exists()

    mixed = ImportService().scan(
        sources=("vscode", "codex"),
        candidate_file=tmp_path / "mixed/candidates.json",
        plan_json=None,
        coordinator="standalone",
        project_root=first,
    )
    assert mixed["scope"] == "project"

    old = json.loads(plan_file.read_text(encoding="utf-8"))
    for key in ("project_root", "plan_id", "resolution_id", "operation_id"):
        old.pop(key)
    old = service._bind_plan_identity(old)
    plan_file.write_text(json.dumps(old), encoding="utf-8")
    if os.name != "nt":
        plan_file.chmod(0o600)
    with pytest.raises(ImportProtocolError, match="missing project_root; rescan"):
        _apply(first, candidate, plan_file)
    assert not (first / "apm.yml").exists()


@pytest.mark.skipif(os.name == "nt", reason="symlink contract is covered on Unix")
def test_project_mcp_rejects_symlinked_workspace_and_native_root(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    real = _workspace(tmp_path, "real", "demo")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(ImportProtocolError, match="canonical non-symlink"):
        _scan(tmp_path, alias)

    root = tmp_path / "workspace"
    root.mkdir()
    (root / ".vscode").symlink_to(real / ".vscode", target_is_directory=True)
    _, _, blocked = _scan(tmp_path, root, "-native-link")
    assert blocked["summary"] == {"unsupported": 1}
    assert not (root / "apm.yml").exists()


def test_project_mcp_two_workspaces_have_independent_identity_and_state(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    first = _workspace(tmp_path, "first", "one")
    second = _workspace(tmp_path, "second", "two")
    c1, p1, plan1 = _scan(tmp_path, first, "-one")
    c2, p2, plan2 = _scan(tmp_path, second, "-two")

    assert plan1["operation_id"] != plan2["operation_id"]
    assert _apply(first, c1, p1)["state"] == "complete"
    assert _apply(second, c2, p2)["state"] == "complete"
    assert {
        item["name"]
        for item in yaml.safe_load((first / "apm.yml").read_text())["dependencies"]["mcp"]
    } == {"one"}
    assert {
        item["name"]
        for item in yaml.safe_load((second / "apm.yml").read_text())["dependencies"]["mcp"]
    } == {"two"}
    assert not (home / ".apm" / "apm.yml").exists()
    assert not (home / ".apm" / "imported").exists()


def test_project_mcp_cli_uses_current_workspace_without_global(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    root = _workspace(tmp_path, "workspace", "demo")
    monkeypatch.chdir(root)
    candidate = tmp_path / "protocol/candidates.json"
    plan = tmp_path / "protocol/plan.json"
    runner = CliRunner()

    scan = runner.invoke(
        cli,
        [
            "import",
            "--from",
            "vscode",
            "--candidate-file",
            str(candidate),
            "--plan-json",
            str(plan),
        ],
    )
    assert scan.exit_code == 0, scan.output
    assert json.loads(scan.stdout)["plan"]["project_root"] == str(root)

    apply = runner.invoke(
        cli,
        [
            "import",
            "--from",
            "vscode",
            "--candidate-file",
            str(candidate),
            "--apply-plan",
            str(plan),
        ],
    )
    assert apply.exit_code == 0, apply.output
    assert json.loads(apply.stdout)["result"]["state"] == "complete"


def test_legacy_global_documents_without_scope_fields_still_decode(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    candidates = {
        "schema_version": 1,
        "coordinator": "standalone",
        "sources": [],
        "candidate_set_id": "",
        "source_preimages": [],
        "candidates": [],
    }
    candidates["candidate_set_id"] = service._candidate_set_identity(candidates)
    service._validate_candidate_envelope(candidates)

    plan = service._plan(candidates)
    plan.pop("scope")
    for key in ("plan_id", "resolution_id", "operation_id"):
        plan.pop(key)
    legacy_plan = service._bind_plan_identity(plan)

    assert service._validate_plan(legacy_plan, candidates) == legacy_plan
