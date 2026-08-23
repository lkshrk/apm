from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from apm_cli.importing.discovery import NativeResource
from apm_cli.importing.special_resources import (
    discover_canvas_resources,
    discover_copilot_app_workflows,
    discover_cowork_resources,
    discover_shared_resources,
    snapshot_hook,
)


def _tree_state(root: Path) -> dict[str, tuple[int, int, int, str | None]]:
    return {
        str(path.relative_to(root)): (
            path.stat().st_size,
            path.stat().st_mode,
            path.stat().st_mtime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
        )
        for path in [root, *sorted(root.rglob("*"))]
    }


def test_shared_roots_emit_once_with_exact_target_union(tmp_path, monkeypatch):
    monkeypatch.delenv("CODEX_HOME", raising=False)
    agents_skill = tmp_path / ".agents" / "skills" / "shared" / "SKILL.md"
    grok_skill = tmp_path / ".grok" / "skills" / "grok" / "SKILL.md"
    for path in (agents_skill, grok_skill):
        path.parent.mkdir(parents=True)
        path.write_text("# skill\n", encoding="utf-8")

    before = _tree_state(tmp_path)
    found = discover_shared_resources(
        ("agent-skills", "codex", "codex", "copilot", "opencode", "grok-build", "grok-cloud"),
        home=tmp_path,
    )

    assert [(item.name, item.targets) for item in found] == [
        ("shared", ("agent-skills", "codex", "copilot", "opencode")),
        ("grok", ("grok-build", "grok-cloud")),
    ]
    assert _tree_state(tmp_path) == before


def test_cowork_dynamic_root_present_and_absent_are_read_only(tmp_path, monkeypatch):
    missing = tmp_path / "missing"
    monkeypatch.setenv("APM_COPILOT_COWORK_SKILLS_DIR", str(missing))
    assert discover_cowork_resources() == []

    root = tmp_path / "cowork-skills"
    skill = root / "daily"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# daily\n", encoding="utf-8")
    monkeypatch.setenv("APM_COPILOT_COWORK_SKILLS_DIR", str(root))
    before = _tree_state(root)

    found = discover_cowork_resources()

    assert [(item.name, item.targets) for item in found] == [("daily", ("copilot-cowork",))]
    assert _tree_state(root) == before


def test_copilot_app_dynamic_db_present_and_absent_are_read_only(tmp_path, monkeypatch):
    missing = tmp_path / "missing.db"
    monkeypatch.setenv("APM_COPILOT_APP_DB", str(missing))
    assert discover_copilot_app_workflows() == []

    db = tmp_path / "data.db"
    conn = sqlite3.connect(db)
    conn.execute(
        """CREATE TABLE workflows (
        id TEXT PRIMARY KEY, name TEXT, prompt TEXT, model TEXT,
        reasoning_effort TEXT, project_id TEXT, interval TEXT,
        schedule_hour INTEGER, schedule_day INTEGER, enabled INTEGER, mode TEXT)"""
    )
    conn.executemany(
        "INSERT INTO workflows VALUES (?, ?, ?, NULL, NULL, NULL, 'manual', 9, 1, 0, NULL)",
        (("apm--owner--pkg--managed", "Managed", "one"), ("native", "Native", "two")),
    )
    conn.commit()
    conn.close()
    monkeypatch.setenv("APM_COPILOT_APP_DB", str(db))
    before = _tree_state(tmp_path)

    found = discover_copilot_app_workflows()

    assert [(item.native.name, item.managed) for item in found] == [
        ("apm--owner--pkg--managed", True),
        ("native", False),
    ]
    assert [item.payload["prompt"] for item in found] == ["one", "two"]
    assert _tree_state(tmp_path) == before


def test_copilot_app_snapshot_reads_wal_without_changing_native_files(tmp_path, monkeypatch):
    db = tmp_path / "data.db"
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute(
        """CREATE TABLE workflows (
        id TEXT PRIMARY KEY, name TEXT, prompt TEXT, model TEXT,
        reasoning_effort TEXT, project_id TEXT, interval TEXT,
        schedule_hour INTEGER, schedule_day INTEGER, enabled INTEGER, mode TEXT)"""
    )
    conn.commit()
    conn.execute(
        "INSERT INTO workflows VALUES ('native', 'Native', 'from wal', NULL, NULL, NULL, "
        "'manual', 9, 1, 0, NULL)"
    )
    conn.commit()
    monkeypatch.setenv("APM_COPILOT_APP_DB", str(db))
    before = _tree_state(tmp_path)

    found = discover_copilot_app_workflows()

    assert [item.payload["prompt"] for item in found] == ["from wal"]
    assert _tree_state(tmp_path) == before
    conn.close()


def test_hook_snapshot_contains_structured_config_and_only_contained_scripts(tmp_path):
    root = tmp_path / ".codex"
    scripts = root / "hooks" / "scripts"
    scripts.mkdir(parents=True)
    contained = scripts / "check.py"
    contained.write_text("print('ok')\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("print('no')\n", encoding="utf-8")
    config = root / "hooks.json"
    payload = {
        "hooks": {"PreToolUse": [{"command": f"python {contained}"}, {"command": str(outside)}]}
    }
    config.write_text(json.dumps(payload), encoding="utf-8")
    native = NativeResource(root, config, "hook", "codex-hooks", ("codex",), "snapshot")
    before = _tree_state(tmp_path)

    snapshot = snapshot_hook(native)

    assert snapshot is not None
    assert snapshot.payload == payload
    assert [item.path for item in snapshot.scripts] == [contained.resolve()]
    assert _tree_state(tmp_path) == before


def test_canvas_custom_snapshot_present_and_absent_are_read_only(tmp_path):
    root = tmp_path / ".copilot"
    assert discover_canvas_resources(root=root) == []
    valid = root / "extensions" / "diagram"
    invalid = root / "extensions" / "missing-marker"
    valid.mkdir(parents=True)
    invalid.mkdir()
    marker = valid / "extension.mjs"
    marker.write_text("export default {}\n", encoding="utf-8")
    before = _tree_state(root)

    found = discover_canvas_resources(root=root)

    assert [(item.kind, item.name, item.targets) for item in found] == [
        ("canvas", "diagram", ("copilot",))
    ]
    assert _tree_state(root) == before
