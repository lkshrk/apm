"""Stable runtime roots for installed Agent Plugin bundles."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from dataclasses import is_dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ..utils.path_security import ensure_path_within, safe_rmtree


def stable_agent_plugin_id(bundle_info: Any) -> str:
    """Return a stable source identity for an Agent Plugin bundle."""
    source_identity = str(
        getattr(bundle_info, "source_identity", "") or getattr(bundle_info, "source_dir", "")
    )
    encoded = source_identity.encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()[:16]
    slug = str(getattr(bundle_info, "package_id", "bundle")).strip() or "bundle"
    return f"{slug}-{digest}"


def agent_plugin_state_root(project_root: Path, *, global_: bool, kind: str) -> Path:
    """Return the canonical retained root for an Agent Plugin state kind."""
    if global_:
        apm_home = Path(os.environ.get("APM_HOME", str(Path.home() / ".apm")))
        return apm_home / kind
    return project_root / "apm_modules" / f".{kind}"


def _replace_bundle_info(bundle_info: Any, **updates: Any) -> Any:
    """Return *bundle_info* with selected fields replaced."""
    if is_dataclass(bundle_info):
        return replace(bundle_info, **updates)
    values = dict(getattr(bundle_info, "__dict__", {}))
    values.update(updates)
    try:
        return bundle_info.__class__(**values)
    except (TypeError, ValueError):
        return SimpleNamespace(**values)


def stage_agent_plugin_bundle(
    bundle_info: Any,
    project_root: Path,
    *,
    global_: bool,
) -> Any:
    """Copy an Agent Plugin to an owned staging root without activating it."""
    if getattr(bundle_info, "retained_root", None) is not None:
        return bundle_info

    stable_id = stable_agent_plugin_id(bundle_info)
    source_parent = agent_plugin_state_root(project_root, global_=global_, kind="agent-plugins")
    data_parent = agent_plugin_state_root(project_root, global_=global_, kind="plugin-data")
    source_root = source_parent / stable_id
    data_root = data_parent / stable_id
    ensure_path_within(source_root, source_parent)
    ensure_path_within(data_root, data_parent)

    source_parent.mkdir(parents=True, exist_ok=True)
    source_dir = Path(bundle_info.source_dir)
    staging_root = Path(tempfile.mkdtemp(prefix=f".{stable_id}-", dir=source_parent))
    ensure_path_within(staging_root, source_parent)
    try:
        shutil.copytree(source_dir, staging_root, dirs_exist_ok=True, symlinks=True)
        if staging_root.is_symlink() or any(path.is_symlink() for path in staging_root.rglob("*")):
            raise ValueError("Agent Plugin bundles cannot contain symbolic links")
    except (OSError, shutil.Error):
        safe_rmtree(staging_root, source_parent)
        raise
    except ValueError:
        safe_rmtree(staging_root, source_parent)
        raise
    return _replace_bundle_info(
        bundle_info,
        source_dir=staging_root,
        retained_root=source_root,
        data_root=data_root,
    )


def commit_agent_plugin_bundle(bundle_info: Any) -> Any:
    """Atomically activate a staged Agent Plugin and preserve plugin data."""
    staging_root = Path(bundle_info.source_dir)
    source_root = Path(bundle_info.retained_root)
    source_parent = source_root.parent
    backup_root = source_parent / f".{source_root.name}.previous"
    ensure_path_within(staging_root, source_parent)
    ensure_path_within(backup_root, source_parent)
    if backup_root.exists():
        safe_rmtree(backup_root, source_parent)
    had_existing_root = source_root.exists()
    try:
        if had_existing_root:
            os.replace(source_root, backup_root)
        os.replace(staging_root, source_root)
    except OSError:
        if not source_root.exists() and backup_root.exists():
            os.replace(backup_root, source_root)
        raise
    if backup_root.exists():
        safe_rmtree(backup_root, source_parent)
    data_root = Path(bundle_info.data_root)
    data_root.mkdir(parents=True, exist_ok=True)
    return _replace_bundle_info(bundle_info, source_dir=source_root)


def discard_staged_agent_plugin_bundle(bundle_info: Any) -> None:
    """Remove an uncommitted Agent Plugin staging root."""
    source_dir = Path(bundle_info.source_dir)
    retained_root = Path(bundle_info.retained_root)
    if source_dir != retained_root and source_dir.exists():
        safe_rmtree(source_dir, retained_root.parent)


def materialize_agent_plugin_bundle(
    bundle_info: Any,
    project_root: Path,
    *,
    global_: bool,
) -> Any:
    """Compatibility facade that stages and immediately commits a bundle."""
    staged = stage_agent_plugin_bundle(bundle_info, project_root, global_=global_)
    return commit_agent_plugin_bundle(staged)
