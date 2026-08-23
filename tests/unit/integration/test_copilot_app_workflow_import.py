from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from apm_cli.importing import service as importing
from apm_cli.importing.service import ImportService
from apm_cli.integration import copilot_app_db as cdb
from apm_cli.integration.prompt_integrator import PromptIntegrator
from apm_cli.integration.targets import KNOWN_TARGETS
from apm_cli.models.apm_package import APMPackage, PackageInfo

_SCHEMA = """
CREATE TABLE workflows (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    prompt TEXT NOT NULL,
    model TEXT,
    reasoning_effort TEXT,
    project_id TEXT,
    interval TEXT NOT NULL CHECK (interval IN ('manual', 'hourly', 'daily', 'weekly')),
    schedule_hour INTEGER NOT NULL DEFAULT 9,
    schedule_day INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_run_at TEXT,
    next_run_at TEXT,
    mode TEXT
);
"""


def _db(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.executescript(_SCHEMA)
    connection.execute("PRAGMA user_version = 13")
    connection.commit()
    connection.close()
    return path


def _row(path: Path, workflow_id: str) -> tuple:
    connection = sqlite3.connect(path)
    try:
        return connection.execute(
            """SELECT name, prompt, model, reasoning_effort, project_id,
                      interval, schedule_hour, schedule_day, enabled, mode
                 FROM workflows WHERE id = ?""",
            (workflow_id,),
        ).fetchone()
    finally:
        connection.close()


def test_import_apply_audit_and_second_scan_are_lossless(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(importing, "_discover_unmanaged_clients", lambda _sources: ([], []))
    db = _db(home / ".copilot" / "data.db")
    install_manifest = importing._install_manifest

    def install_imported_workflow(manifest_path, targets):
        assert targets == ["copilot-app"]
        result = install_manifest(manifest_path, [])
        package_path = next((home / ".apm" / "imported" / "command").iterdir())
        package_info = PackageInfo(
            package=APMPackage.from_apm_yml(package_path / "apm.yml"),
            install_path=package_path,
        )
        PromptIntegrator().integrate_prompts_for_target(
            KNOWN_TARGETS["copilot-app"], package_info, home
        )
        return result

    monkeypatch.setattr(importing, "_install_manifest", install_imported_workflow)
    expected = (
        "Reviewed name",
        "reviewed prompt\n",
        "claude-sonnet-4.5",
        "high",
        "existing-project",
        "weekly",
        23,
        6,
        1,
        "autopilot",
    )
    connection = sqlite3.connect(db)
    connection.execute(
        """INSERT INTO workflows (
               id, name, prompt, model, reasoning_effort, project_id,
               interval, schedule_hour, schedule_day, enabled, mode
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        ("native-workflow", *expected),
    )
    connection.commit()
    connection.close()

    candidates = tmp_path / "candidates.json"
    plan_path = tmp_path / "plan.json"
    service = ImportService()
    plan = service.scan(
        sources=("copilot-app",),
        candidate_file=candidates,
        plan_json=plan_path,
        coordinator="standalone",
    )
    result = service.apply(
        candidate_file=candidates,
        plan_file=plan_path,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )

    assert result["state"] == "complete"
    assert result["operation_id"] == plan["operation_id"]
    connection = sqlite3.connect(db)
    managed_id = connection.execute("SELECT id FROM workflows WHERE id LIKE 'apm--%'").fetchone()[0]
    connection.close()
    assert _row(db, managed_id) == expected

    second_candidates = tmp_path / "second-candidates.json"
    service.scan(
        sources=("copilot-app",),
        candidate_file=second_candidates,
        plan_json=None,
        coordinator="standalone",
    )
    second = json.loads(second_candidates.read_text(encoding="utf-8"))
    assert not [
        candidate
        for candidate in second["candidates"]
        if candidate.get("payload", {}).get("import_layout") == "workflow"
    ]


def test_malformed_import_metadata_fails_before_database_write(monkeypatch, tmp_path):
    home = tmp_path / "home"
    package = home / ".apm" / "imported" / "command" / "bad"
    prompt = package / ".apm" / "prompts" / "bad.prompt.md"
    prompt.parent.mkdir(parents=True)
    prompt.write_text("---\ninterval: manual\n---\nhello", encoding="utf-8")
    (package / ".apm-import.json").write_text("{broken", encoding="utf-8")
    db = _db(home / ".copilot" / "data.db")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("APM_COPILOT_APP_DB", str(db))
    package_info = PackageInfo(
        package=APMPackage(name="bad", version="1.0.0", package_path=package),
        install_path=package,
    )

    with pytest.raises(ValueError, match="invalid imported Copilot App workflow metadata"):
        PromptIntegrator().integrate_prompts_for_target(
            KNOWN_TARGETS["copilot-app"], package_info, tmp_path
        )
    connection = sqlite3.connect(db)
    assert connection.execute("SELECT COUNT(*) FROM workflows").fetchone()[0] == 0
    connection.close()


def test_ordinary_deploy_still_forces_disabled_and_rejects_autopilot(tmp_path):
    db = _db(tmp_path / "data.db")
    workflow_id = cdb.namespaced_id("owner", "package", "prompt")
    cdb.deploy_workflow(
        db,
        cdb.WorkflowRow(
            id=workflow_id,
            name="ordinary",
            prompt="hello",
            enabled=1,
            mode="plan",
        ),
    )
    assert _row(db, workflow_id)[8] == 0
    with pytest.raises(ValueError, match="autopilot"):
        cdb.deploy_workflow(
            db,
            cdb.WorkflowRow(
                id=cdb.namespaced_id("owner", "package", "autopilot"),
                name="ordinary",
                prompt="hello",
                mode="autopilot",
            ),
        )


def test_imported_source_drift_rolls_back_before_replacement(tmp_path):
    db = _db(tmp_path / "data.db")
    connection = sqlite3.connect(db)
    connection.execute(
        """INSERT INTO workflows (
               id, name, prompt, interval, schedule_hour, schedule_day, enabled
           ) VALUES ('native', 'changed', 'prompt', 'manual', 9, 1, 1)"""
    )
    connection.commit()
    connection.close()
    managed_id = cdb.namespaced_id("owner", "package", "prompt")

    with pytest.raises(ValueError, match="source changed after review"):
        cdb.deploy_workflow(
            db,
            cdb.WorkflowRow(
                id=managed_id,
                name="reviewed",
                prompt="prompt",
                enabled=1,
            ),
            preserve_imported_state=True,
            source_workflow_id="native",
        )

    connection = sqlite3.connect(db)
    assert connection.execute("SELECT name FROM workflows WHERE id = 'native'").fetchone() == (
        "changed",
    )
    assert (
        connection.execute("SELECT 1 FROM workflows WHERE id = ?", (managed_id,)).fetchone() is None
    )
    connection.close()
