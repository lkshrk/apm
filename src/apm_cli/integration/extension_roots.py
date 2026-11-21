"""Recover native deployment roots from attributed ownership, not current env."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from apm_cli.core.deployment_ledger import DeploymentLedgerCodec
from apm_cli.core.deployment_state import LocatorKind
from apm_cli.integration.extension_integrator import RECEIPT_FILENAME, RESERVED_EXTENSION_NAMES
from apm_cli.integration.targets import KNOWN_TARGETS, TargetProfile


def _safe_value(value: str) -> Path | None:
    path = Path(value)
    if not value or "\\" in value or ".." in path.parts or "://" in value:
        return None
    return path


def _receipt_bundle(project_root: Path, path: Path) -> Path | None:
    """Return the package directory a native receipt path owns, if it has that shape."""
    if (
        path.name == RECEIPT_FILENAME
        and len(path.parts) >= 3
        and path.parent.parent.name == "extensions"
        and path.parent.name not in RESERVED_EXTENSION_NAMES
    ):
        return project_root / path.parent
    return None


def recorded_omp_roots(
    lockfile, project_root: Path, *, dependency_keys: set[str] | None = None
) -> set[Path]:
    """Return ledger-attributed native roots, including missing or edited ones.

    This is discovery authority only, never proof that a file may be deleted.
    Callers must still verify receipt/payload hashes and symlink ancestry before
    writes. Keeping damaged roots visible lets audit diagnose their drift.
    Legacy paths without explicit omp attribution cannot authorize custom roots.
    Files inside a receipt-backed native bundle are package resources: a bundled
    ``apm-hooks-runtime.json`` or ``extensions/apm-hooks-*/index.ts`` never
    implies a deployment root, whatever the receipt's own hash or owner state.
    """
    if lockfile is None:
        return set()
    records = [
        record
        for record in DeploymentLedgerCodec.from_lockfile(lockfile).records.values()
        if record.locator.target == "omp" and record.locator.kind == LocatorKind.PROJECT_RELATIVE
    ]
    bundles: set[Path] = set()
    for record in records:
        path = _safe_value(DeploymentLedgerCodec.legacy_value(record.locator))
        bundle = _receipt_bundle(project_root, path) if path is not None else None
        if bundle is not None:
            bundles.add(bundle)
    roots: set[Path] = set()
    for record in records:
        if dependency_keys is not None and not dependency_keys.intersection(record.owners):
            continue
        if not record.active_owner or record.active_owner not in record.owners:
            continue
        digest = (record.content_hash or "").removeprefix("sha256:")
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            continue
        path = _safe_value(DeploymentLedgerCodec.legacy_value(record.locator))
        if path is None:
            continue
        absolute = project_root / path
        if (
            path.name == RECEIPT_FILENAME
            and len(path.parts) >= 3
            and path.parent.parent.name == "extensions"
        ):
            if dependency_keys is not None and record.active_owner not in dependency_keys:
                continue
            root = absolute.parent.parent.parent
        elif any(absolute.is_relative_to(bundle) for bundle in bundles):
            continue
        elif path.name == "apm-hooks-runtime.json":
            root = absolute.parent
        elif (
            len(path.parts) >= 3
            and path.parts[-3] == "extensions"
            and path.parts[-2] in ("apm-hooks-project", "apm-hooks-user")
            and path.name == "index.ts"
        ):
            root = absolute.parent.parent.parent
        else:
            continue
        # A native deployment root cannot be the filesystem root itself.
        if root != Path(root.anchor):
            roots.add(root)
    return roots


def recorded_omp_profiles(
    lockfile,
    project_root: Path,
    *,
    dependency_keys: set[str] | None = None,
    user_scope: bool = False,
) -> list[TargetProfile]:
    """Recover narrow cleanup profiles; atomic bundle gates remain mandatory.

    Historical user rows may carry project scope labels. The caller's scope
    does not invalidate their explicit native target and owner attribution.
    Shared hook runtime artifacts are recognized but never deleted per-file.
    """
    profile = KNOWN_TARGETS["omp"]
    return [
        replace(
            profile,
            root_dir=root.as_posix(),
            user_root_dir=root.as_posix(),
            resolved_deploy_root=None,
            user_root_resolver=None,
            primitives={"extensions": profile.primitives["extensions"]},
            hooks_config_display=None,
            pack_prefixes=(root.as_posix().rstrip("/") + "/",),
        )
        for root in sorted(
            recorded_omp_roots(lockfile, project_root, dependency_keys=dependency_keys)
        )
    ]
