"""Tests for stable Agent Plugin runtime materialization."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from apm_cli.bundle.local_bundle import detect_local_bundle
from apm_cli.install.agent_plugin_runtime import (
    commit_agent_plugin_bundle,
    discard_staged_agent_plugin_bundle,
    materialize_agent_plugin_bundle,
    stage_agent_plugin_bundle,
)
from apm_cli.install.local_bundle_handler import _bundle_owner_key


def _write_agent_plugin(path: Path, *, description: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "plugin.json").write_text(
        (
            '{"$schema":"https://agent-plugins.org/schemas/1.0.0/'
            'plugin.schema.json","name":"stable-plugin",'
            f'"description":"{description}"}}'
        ),
        encoding="utf-8",
    )


def test_materialization_uses_manifest_name_and_preserves_data(tmp_path: Path) -> None:
    source = tmp_path / "source"
    project = tmp_path / "project"
    _write_agent_plugin(source, description="first")
    info = detect_local_bundle(source)
    assert info is not None
    assert info.package_id == "stable-plugin"

    first = materialize_agent_plugin_bundle(info, project, global_=False)
    assert first.retained_root is not None
    assert first.data_root is not None
    (first.data_root / "state.json").write_text("persistent", encoding="utf-8")

    (source / "plugin.json").write_text(
        (
            '{"$schema":"https://agent-plugins.org/schemas/1.0.0/'
            'plugin.schema.json","name":"stable-plugin",'
            '"description":"updated"}'
        ),
        encoding="utf-8",
    )
    updated_info = detect_local_bundle(source)
    assert updated_info is not None
    second = materialize_agent_plugin_bundle(updated_info, project, global_=False)

    assert second.retained_root == first.retained_root
    assert second.data_root == first.data_root
    assert (second.data_root / "state.json").read_text(encoding="utf-8") == "persistent"
    assert "updated" in (second.retained_root / "plugin.json").read_text(encoding="utf-8")


def test_service_owner_is_stable_across_bundle_versions(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_agent_plugin(source, description="first")
    first = detect_local_bundle(source)
    assert first is not None

    _write_agent_plugin(source, description="updated")
    second = detect_local_bundle(source)
    assert second is not None
    first = replace(first, plugin_json={**first.plugin_json, "version": "1.0.0"})
    second = replace(second, plugin_json={**second.plugin_json, "version": "1.1.0"})

    assert _bundle_owner_key(first) == _bundle_owner_key(second)


def test_dry_run_caller_can_skip_materialization(tmp_path: Path) -> None:
    source = tmp_path / "source"
    project = tmp_path / "project"
    _write_agent_plugin(source, description="dry run")
    info = detect_local_bundle(source)
    assert info is not None

    assert info.retained_root is None
    assert not (project / "apm_modules").exists()


def test_staged_update_does_not_activate_until_commit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    project = tmp_path / "project"
    _write_agent_plugin(source, description="first")
    info = detect_local_bundle(source)
    assert info is not None
    active = materialize_agent_plugin_bundle(info, project, global_=False)
    _write_agent_plugin(source, description="updated")
    updated_info = detect_local_bundle(source)
    assert updated_info is not None

    staged = stage_agent_plugin_bundle(updated_info, project, global_=False)

    assert "first" in (active.retained_root / "plugin.json").read_text(encoding="utf-8")
    assert "updated" in (staged.source_dir / "plugin.json").read_text(encoding="utf-8")
    discard_staged_agent_plugin_bundle(staged)
    assert "first" in (active.retained_root / "plugin.json").read_text(encoding="utf-8")

    staged = stage_agent_plugin_bundle(updated_info, project, global_=False)
    committed = commit_agent_plugin_bundle(staged)
    assert "updated" in (committed.retained_root / "plugin.json").read_text(encoding="utf-8")


def test_materialization_rejects_symlinks_without_replacing_existing_root(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    project = tmp_path / "project"
    _write_agent_plugin(source, description="first")
    info = detect_local_bundle(source)
    assert info is not None
    first = materialize_agent_plugin_bundle(info, project, global_=False)

    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    (source / "linked.txt").symlink_to(outside)
    updated_info = detect_local_bundle(source)
    assert updated_info is not None

    with pytest.raises(ValueError, match="symbolic links"):
        materialize_agent_plugin_bundle(updated_info, project, global_=False)

    assert "first" in (first.retained_root / "plugin.json").read_text(encoding="utf-8")
    assert not (first.retained_root / "linked.txt").exists()
