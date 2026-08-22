"""Scratch projection helpers for audit target deployment roots."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from apm_cli.integration.targets import TargetProfile

_EXTERNAL_REPLAY_ROOT = ".apm-audit-targets"


def replay_target(target: TargetProfile) -> TargetProfile:
    """Return a scratch-contained profile for replay-only integration."""
    if target.managed_deploy_root is None:
        return target
    return replace(
        target,
        root_dir=f"{_EXTERNAL_REPLAY_ROOT}/{target.name}",
        resolved_deploy_root=None,
    )


def external_replay_root(scratch_root: Path, target: TargetProfile) -> Path:
    """Return the scratch projection root for an external target."""
    return scratch_root / _EXTERNAL_REPLAY_ROOT / target.name


def claims_for_root(
    claims: dict[str, str],
    root: Path,
    *,
    absolute_only: bool,
) -> dict[str, str]:
    """Rebase lock claims governed by *root* into comparison-relative paths."""
    root = root.resolve()
    rebased: dict[str, str] = {}
    for path, owner in claims.items():
        candidate = Path(path)
        if candidate.is_absolute():
            try:
                relative = candidate.resolve().relative_to(root)
            except ValueError:
                continue
            rebased[relative.as_posix()] = owner
        elif not absolute_only:
            rebased[path] = owner
    return rebased
