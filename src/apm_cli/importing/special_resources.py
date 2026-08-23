"""Read-only discovery for shared, dynamic, and snapshot native state."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import sqlite3
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from apm_cli.integration.canvas_integrator import CANVAS_MARKER
from apm_cli.integration.copilot_app_db import (
    is_apm_managed_id,
    resolve_copilot_app_db_path,
)
from apm_cli.integration.copilot_cowork_paths import resolve_copilot_cowork_skills_dir

from .discovery import NativeResource, discover_filesystem_resources, path_boundary_error


@dataclass(frozen=True)
class CopilotWorkflowResource:
    """One immutable view of a Copilot App workflow row and its DB preimage."""

    native: NativeResource
    payload: dict[str, Any]
    managed: bool


@dataclass(frozen=True)
class HookSnapshot:
    """A structured hook config plus every contained local script."""

    native: NativeResource
    payload: dict[str, Any]
    scripts: tuple[NativeResource, ...]
    blocked_reason: str | None = None


def discover_shared_resources(
    targets: Iterable[str], *, home: Path | None = None
) -> list[NativeResource]:
    """Return path-aggregated shared mappings with their exact target union."""
    return [
        resource
        for resource in discover_filesystem_resources(targets, home=home)
        if resource.strategy == "shared"
    ]


def discover_cowork_resources() -> list[NativeResource]:
    """Discover skills directly below the runtime-resolved Cowork skills root."""
    root = resolve_copilot_cowork_skills_dir()
    if root is None:
        return []
    if error := path_boundary_error(root, root):
        return [
            NativeResource(
                root, root, "unsupported", "copilot-cowork", ("copilot-cowork",), "custom", error
            )
        ]
    if not root.is_dir():
        return []
    resolved_root = root.resolve(strict=False)
    return [
        NativeResource(resolved_root, child, "skill", child.name, ("copilot-cowork",), "custom")
        for child in sorted(root.iterdir())
        if child.is_dir()
        and not child.is_symlink()
        and (child / "SKILL.md").is_file()
        and not (child / "SKILL.md").is_symlink()
        and child.resolve().is_relative_to(resolved_root)
    ]


def discover_copilot_app_workflows() -> list[CopilotWorkflowResource]:
    """Read Copilot App workflows from a temporary DB/WAL snapshot."""
    db_path = resolve_copilot_app_db_path()
    if db_path is None:
        return []
    if db_path.is_symlink():
        raise ValueError("unsafe Copilot App database path")
    resolved = db_path.resolve()
    with tempfile.TemporaryDirectory(prefix="apm-copilot-app-import-") as temp_dir:
        snapshot = Path(temp_dir) / resolved.name
        shutil.copy2(resolved, snapshot)
        wal = Path(f"{resolved}-wal")
        if wal.is_file():
            shutil.copy2(wal, Path(f"{snapshot}-wal"))
        conn = sqlite3.connect(f"{snapshot.as_uri()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                """
                SELECT id, name, prompt, model, reasoning_effort, project_id,
                       interval, schedule_hour, schedule_day, enabled, mode
                  FROM workflows ORDER BY id
                """
            ).fetchall()
        finally:
            conn.close()
    root = resolved.parent
    return [
        CopilotWorkflowResource(
            NativeResource(root, resolved, "command", str(row["id"]), ("copilot-app",), "custom"),
            dict(row),
            is_apm_managed_id(str(row["id"])),
        )
        for row in rows
    ]


def discover_canvas_resources(*, root: Path) -> list[NativeResource]:
    """Discover valid Copilot canvas bundles under a resolved native root."""
    base = root / "extensions"
    if error := path_boundary_error(root, base):
        return [
            NativeResource(
                root, base, "unsupported", "copilot-canvas", ("copilot",), "custom", error
            )
        ]
    if not base.is_dir():
        return []
    resolved_root = root.resolve(strict=False)
    resources: list[NativeResource] = []
    for child in sorted(base.iterdir()):
        error = path_boundary_error(root, child)
        if error:
            resources.append(
                NativeResource(
                    root, child, "unsupported", child.name, ("copilot",), "custom", error
                )
            )
            continue
        marker = child / CANVAS_MARKER
        if error := path_boundary_error(root, marker):
            resources.append(
                NativeResource(
                    root, marker, "unsupported", child.name, ("copilot",), "custom", error
                )
            )
        elif child.is_dir() and marker.is_file():
            resources.append(
                NativeResource(resolved_root, child, "canvas", child.name, ("copilot",), "custom")
            )
    return resources


def snapshot_hook(resource: NativeResource) -> HookSnapshot | None:
    """Parse a hook config and retain only scripts contained by its native root."""
    if resource.kind != "hook":
        return None
    if resource.blocked_reason:
        return HookSnapshot(resource, {}, (), resource.blocked_reason)
    if not resource.path.is_file() or resource.path.is_symlink():
        return HookSnapshot(resource, {}, (), "unsafe-source-path")
    try:
        payload = json.loads(resource.path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return HookSnapshot(resource, {}, (), "malformed-hook-document")
    if not isinstance(payload, dict):
        return HookSnapshot(resource, {}, (), "malformed-hook-document")
    root = resource.root.resolve(strict=False)
    found: set[Path] = set()
    for value in _strings(payload):
        try:
            tokens = shlex.split(value, posix=os.name != "nt")
        except ValueError:
            continue
        for token in tokens:
            candidate = Path(token).expanduser()
            if not candidate.is_absolute():
                candidate = resource.path.parent / candidate
            if candidate.is_symlink():
                return HookSnapshot(resource, {}, (), "unsafe-source-path")
            resolved = candidate.resolve(strict=False)
            if resolved.is_file() and not resolved.is_symlink() and resolved.is_relative_to(root):
                found.add(resolved)
    scripts = tuple(
        NativeResource(
            resource.root,
            path,
            "hook",
            f"{resource.name}-{path.stem}",
            resource.targets,
            "snapshot",
        )
        for path in sorted(found)
    )
    return HookSnapshot(resource, payload, scripts)


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for child in value.values():
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)
    elif isinstance(value, str):
        yield value
