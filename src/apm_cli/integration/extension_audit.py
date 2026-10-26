"""Read-only ownership audit for native omp extension bundles and hook runtime.

Audit discovery is ledger-driven: a native package root exists here only when
an explicit ``omp`` deployment row claims its receipt (or a payload file below
a governed ``extensions`` root whose receipt row is gone). Directories are
never listed to find candidates, so unmanaged ambient siblings stay untouched.

Bundle verdicts come from ``ExtensionIntegrator._owned``, the same receipt /
ledger / exact-tree gate install, uninstall and cleanup use. Only a failed
verdict is explained, so the reported reasons can never disagree with the gate.
The hook bridge and runtime state are owned by the hook integrator; they are
verified through its side-effect-free bridge verifier, never by editing
``hooks.json``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from apm_cli.core.deployment_ledger import DeploymentLedgerCodec
from apm_cli.core.deployment_state import DeploymentLocator, LocatorKind
from apm_cli.hook_contract import HookContractError
from apm_cli.integration.extension_integrator import (
    RECEIPT_FILENAME,
    RESERVED_EXTENSION_NAMES,
    ExtensionIntegrator,
)
from apm_cli.integration.omp_hook_integrator import (
    OMP_HOOK_BRIDGES,
    OMP_HOOK_RUNTIME_STATE,
    _read_object,
    _verify_owned_namespace_bridge,
)
from apm_cli.utils.path_security import has_symlink_component
from apm_cli.utils.paths import portable_relpath

if TYPE_CHECKING:
    from apm_cli.deps.lockfile import LockFile
    from apm_cli.integration.targets import TargetProfile

_OMP = "omp"
_EXTENSIONS = "extensions"
_BRIDGE_SCOPES = {
    PurePosixPath(path).parent.name: scope for scope, path in OMP_HOOK_BRIDGES.items()
}
_LISTED = 5
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True)
class NativeIntegrityFailure:
    """One ownership failure for a whole native bundle or hook runtime."""

    kind: str  # "bundle" | "runtime"
    root: str
    reasons: tuple[str, ...]

    def detail(self) -> str:
        """Render the single audit detail line for this bundle or runtime."""
        return f"native-{self.kind}: {self.root}: {'; '.join(self.reasons)}"


def _names(label: str, items: Iterable[str]) -> str | None:
    ordered = sorted(dict.fromkeys(items))
    if not ordered:
        return None
    shown = ", ".join(ordered[:_LISTED])
    extra = f" (+{len(ordered) - _LISTED} more)" if len(ordered) > _LISTED else ""
    return f"{label} {shown}{extra}"


_LINKED = "symlinked root or ancestor"


def _linked_ancestry(path: Path) -> bool:
    """lstat every component of *path* from the filesystem root; never follows a link."""
    absolute = path.absolute()
    return has_symlink_component(Path(absolute.anchor), absolute)


def _lexical_under(base: Path, value: str) -> Path | None:
    """Join a ledger locator under *base* by name only, without touching the filesystem."""
    if "://" in value:
        return None
    candidate = Path(value.rstrip("/"))
    if not candidate.parts or ".." in candidate.parts:
        return None
    return base / candidate


def _linked_below(path: Path, roots: Iterable[Path]) -> bool:
    """Whether *path*'s parent chain below a governing root crosses a link (lstat only)."""
    return any(
        path.is_relative_to(root) and has_symlink_component(root, path.parent) for root in roots
    )


def _key(path: Path, project_root: Path) -> str:
    """Project-relative POSIX identity by name; resolving would regroup a linked path.

    Paths outside the project keep their lexical absolute form for the same reason.
    """
    try:
        return path.relative_to(project_root).as_posix()
    except ValueError:
        return path.as_posix()


def _explain_bundle(
    root: Path, project_root: Path, managed: set[str], ledger_hashes: dict[str, str | None]
) -> list[str]:
    """Name why the ownership gate rejected *root*; read-only."""
    from apm_cli.utils.content_hash import compute_file_hash

    # Callers lstat the root's ancestry first (_linked_ancestry); nothing here follows a link.
    if not root.is_dir():
        return ["root is not a directory"]

    reasons: list[str] = []
    declared: dict = {}
    receipt = root / RECEIPT_FILENAME
    if receipt.is_symlink() or not receipt.is_file():
        reasons.append("receipt missing or not a regular file")
    else:
        key = portable_relpath(receipt, project_root)
        try:
            if key not in managed:
                reasons.append("receipt not claimed by ledger")
            elif ledger_hashes.get(key) != compute_file_hash(receipt):
                reasons.append("receipt edited or without ledger hash")
            data = json.loads(receipt.read_text(encoding="utf-8"))
            files = data["files"]
            if data.get("version") != 1 or not isinstance(files, dict):
                raise ValueError("unsupported receipt")
            declared = dict(files)
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            reasons.append("receipt invalid")

    missing: list[str] = []
    modified: list[str] = []
    unrecorded: list[str] = []
    linked: list[str] = []
    other: list[str] = []
    unsafe: list[str] = []
    for relative, digest in declared.items():
        parts = PurePosixPath(relative).parts if isinstance(relative, str) else ()
        if (
            not parts
            or not isinstance(digest, str)
            or "\\" in relative
            or ":" in relative
            or PurePosixPath(relative).is_absolute()
            or ".." in parts
            or relative == RECEIPT_FILENAME
        ):
            unsafe.append(str(relative))
            continue
        path = root / relative
        if has_symlink_component(root, path) or path.is_symlink():
            linked.append(relative)
        elif not os.path.lexists(path):
            missing.append(relative)
        elif not path.is_file():
            other.append(relative)
        else:
            if portable_relpath(path, project_root) not in managed:
                unrecorded.append(relative)
            try:
                if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    modified.append(relative)
            except OSError:
                modified.append(relative)

    expected_files = {relative for relative in declared if isinstance(relative, str)} | {
        RECEIPT_FILENAME
    }
    expected_dirs = {
        parent.as_posix()
        for relative in expected_files
        for parent in PurePosixPath(relative).parents
        if parent != PurePosixPath(".")
    }
    foreign: list[str] = []
    unreadable: list[str] = []

    def _walk_error(error: OSError) -> None:
        unreadable.append(os.path.relpath(error.filename, root) if error.filename else ".")

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=_walk_error):
        base = Path(directory)
        kept = []
        for name in sorted(dirs):
            relative = (base / name).relative_to(root).as_posix()
            # Foreign trees are reported once at their top; links are never entered.
            if relative not in expected_dirs or (base / name).is_symlink():
                foreign.append(relative + "/")
            else:
                kept.append(name)
        dirs[:] = kept
        for name in sorted(files):
            relative = (base / name).relative_to(root).as_posix()
            if relative not in expected_files:
                foreign.append(relative)

    for text in (
        _names("unsafe receipt path", unsafe),
        _names("missing", missing),
        _names("modified", modified),
        _names("unrecorded", unrecorded),
        _names("symlink", linked),
        _names("non-regular", other),
        _names("foreign", foreign),
        _names("unreadable", unreadable),
    ):
        if text:
            reasons.append(text)
    return reasons or ["receipt, ledger or tree verification failed"]


def _runtime_reasons(root: Path, scope: str | None) -> list[str]:
    """Run the hook owner's read-only bridge/state verifier for *root*."""
    try:
        if scope is None:
            state = _read_object(root / OMP_HOOK_RUNTIME_STATE)
            if not state:
                return []  # absence is the deployed-files check's signal
            scope = state["scope"] if isinstance(state.get("scope"), str) else "project"
        _verify_owned_namespace_bridge(root, scope)
    except (HookContractError, OSError, ValueError) as exc:
        return [str(exc)]
    return []


def audit_native_extension_ownership(
    project_root: Path,
    lock: LockFile,
    targets: Sequence[TargetProfile],
    resolve_project_path: Callable[[str], Path | None],
) -> tuple[NativeIntegrityFailure, ...]:
    """Return one failure per damaged ledger-owned native bundle or hook runtime.

    ``resolve_project_path`` is the caller's containment-checked resolver for
    project-relative locator values, so roots resolve exactly like the hash
    loop's claims (including historical custom roots recorded by the ledger).
    Absent roots are skipped: absence belongs to the deployed-files check.
    """
    ledger = DeploymentLedgerCodec.from_lockfile(lock)
    claims: dict[Path, str | None] = {}
    unresolved: list[str] = []

    deploy_roots = tuple(
        target.managed_deploy_root for target in targets if target.managed_deploy_root is not None
    )

    def _resolve(locator: DeploymentLocator) -> Path | None:
        # A claim below a link keeps its lexical identity: the resolvers follow links
        # (or refuse them), which would regroup the claim under the link's target or drop it.
        if locator.kind == LocatorKind.PROJECT_RELATIVE:
            lexical = _lexical_under(project_root, locator.value)
            if lexical is not None and _linked_below(lexical, (project_root, *deploy_roots)):
                return lexical
            return resolve_project_path(locator.value)
        for target in targets:
            if target.name != locator.target or target.managed_deploy_root is None:
                continue
            lexical = _lexical_under(target.managed_deploy_root, locator.value)
            if (
                lexical is not None
                and not Path(locator.value).is_absolute()
                and has_symlink_component(target.managed_deploy_root, lexical.parent)
            ):
                return lexical
            try:
                resolved = DeploymentLedgerCodec.resolve_locator(
                    locator, project_root=project_root, target=target
                )
            except (OSError, RuntimeError, ValueError):
                continue
            if isinstance(resolved, Path):
                return resolved
        return None

    for record in ledger.records.values():
        locator = record.locator
        if locator.target != _OMP or locator.kind == LocatorKind.URI:
            continue
        if not record.owners or not record.active_owner:
            continue
        path = _resolve(locator)
        if path is not None:
            claims[path] = record.content_hash
        elif PurePosixPath(locator.value).name == RECEIPT_FILENAME:
            unresolved.append(locator.value)

    bases = set()
    for target in targets:
        mapping = target.primitives.get(_EXTENSIONS) if target.name == _OMP else None
        if mapping is not None:
            bases.add(project_root / (mapping.deploy_root or target.root_dir) / mapping.subdir)

    bundle_roots: set[Path] = set()
    for path in claims:
        holder = path.parent
        if (
            path.name == RECEIPT_FILENAME
            and holder.parent.name == _EXTENSIONS
            and holder.name not in RESERVED_EXTENSION_NAMES
        ):
            bundle_roots.add(holder)
            continue
        for base in bases:
            if path.is_relative_to(base) and len(path.relative_to(base).parts) >= 2:
                name = path.relative_to(base).parts[0]
                if name not in RESERVED_EXTENSION_NAMES:
                    bundle_roots.add(base / name)

    # Files inside a bundle are package resources (even a bundled
    # apm-hooks-runtime.json or extensions/apm-hooks-*/index.ts), never hook runtime.
    runtime_roots: dict[Path, str | None] = {}
    for path in claims:
        if any(path.is_relative_to(root) for root in bundle_roots):
            continue
        holder = path.parent
        if holder.parent.name == _EXTENSIONS and holder.name in _BRIDGE_SCOPES:
            runtime_roots.setdefault(holder.parent.parent, _BRIDGE_SCOPES[holder.name])
        elif path.name == OMP_HOOK_RUNTIME_STATE:
            runtime_roots.setdefault(holder, None)

    managed = {_key(path, project_root) for path in claims}
    ledger_hashes = {_key(path, project_root): value for path, value in claims.items()}

    def _unproven(root: Path, runtime: bool) -> str | None:
        """Name claimed files below *root* whose ledger hash is missing or malformed."""
        names = []
        for path, value in claims.items():
            if runtime:
                owned = (path.parent == root and path.name == OMP_HOOK_RUNTIME_STATE) or (
                    path.parent.parent.parent == root
                    and path.parent.parent.name == _EXTENSIONS
                    and path.parent.name in _BRIDGE_SCOPES
                )
            else:
                owned = path.is_relative_to(root)
            if (
                owned
                and (not isinstance(value, str) or _DIGEST.fullmatch(value) is None)
                and os.path.lexists(path)
                and not path.is_dir()
            ):
                names.append(path.relative_to(root).as_posix())
        return _names("ledger hash missing or invalid for", names)

    failures = [
        NativeIntegrityFailure("bundle", value, ("receipt path cannot be resolved",))
        for value in sorted(set(unresolved))
    ]
    for root in sorted(bundle_roots):
        # lstat the root's lexical ancestry before anything below it is opened or stat'ed.
        if _linked_ancestry(root):
            failures.append(NativeIntegrityFailure("bundle", _key(root, project_root), (_LINKED,)))
            continue
        if not os.path.lexists(root):
            continue
        verdict = ExtensionIntegrator._owned(
            root, project_root, managed, managed_file_hashes=ledger_hashes
        )
        reasons = (
            []
            if verdict is not None
            else _explain_bundle(root, project_root, managed, ledger_hashes)
        )
        if unproven := _unproven(root, runtime=False):
            reasons.append(unproven)
        if reasons:
            failures.append(
                NativeIntegrityFailure("bundle", _key(root, project_root), tuple(reasons))
            )
    for root, scope in sorted(runtime_roots.items()):
        if _linked_ancestry(root):
            failures.append(NativeIntegrityFailure("runtime", _key(root, project_root), (_LINKED,)))
            continue
        reasons = _runtime_reasons(root, scope)
        if unproven := _unproven(root, runtime=True):
            reasons.append(unproven)
        if reasons:
            failures.append(
                NativeIntegrityFailure("runtime", _key(root, project_root), tuple(reasons))
            )
    return tuple(failures)
