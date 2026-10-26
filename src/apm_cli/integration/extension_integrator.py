"""Owned, resource-preserving native omp extension package deployment."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from apm_cli.integration.base_integrator import BaseIntegrator, IntegrationResult
from apm_cli.integration.canvas_integrator import CanvasIntegrator
from apm_cli.integration.extension_discovery import (
    ExtensionBundle,
    find_extension_bundles,
    native_extension_name,
)
from apm_cli.utils.path_security import ensure_path_within, has_symlink_component
from apm_cli.utils.paths import portable_relpath

RECEIPT_FILENAME = ".apm-extension.json"
RESERVED_EXTENSION_NAMES = frozenset({"apm-hooks-project", "apm-hooks-user"})
_IGNORED_DIRS = frozenset({".git", "apm_modules", "__pycache__"})


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _has_destination_link(path: Path) -> bool:
    absolute = path.absolute()
    return has_symlink_component(Path(absolute.anchor), absolute)


def _native_names(root: Path, entries: tuple[str, ...]) -> set[str]:
    names = []
    for entry in entries:
        path = root / entry
        names.append(native_extension_name(path))
    if len(set(names)) != len(names):
        raise ValueError(f"Duplicate native extension names in {root}: {names}")
    return set(names)


def _receipt_root_is_safe(root: Path, receipt: Path) -> bool:
    """Return whether the root and receipt are real (no-follow) directory/file."""
    return (
        root.is_dir()
        and not _has_destination_link(root)
        and receipt.is_file()
        and not receipt.is_symlink()
    )


def _read_receipt_hashes(
    receipt: Path,
    project_root: Path,
    owner: str | None,
    managed_file_hashes,
) -> dict[str, str] | None:
    """Load receipt file hashes after baseline, version and owner identity checks."""
    if managed_file_hashes is not None:
        from apm_cli.utils.content_hash import compute_file_hash

        expected = managed_file_hashes.get(portable_relpath(receipt, project_root))
        if expected != compute_file_hash(receipt):
            return None
    data = json.loads(receipt.read_text(encoding="utf-8"))
    hashes = data["files"]
    if data.get("version") != 1 or not isinstance(hashes, dict):
        return None
    if owner is not None and data.get("owner") != owner:
        return None
    return hashes


def _receipt_entry_is_valid(relative, digest) -> bool:
    """Return whether a receipt entry names a safe relative payload path and digest."""
    if not isinstance(relative, str) or not relative or "\\" in relative or ":" in relative:
        return False
    parts = Path(relative).parts
    if Path(relative).is_absolute() or ".." in parts or relative == RECEIPT_FILENAME:
        return False
    return isinstance(digest, str)


def _claimed_payload_is_verified(
    root: Path, project_root: Path, managed: set[str], hashes: dict[str, str]
) -> bool:
    """Return whether every claimed file is a managed regular file with its raw hash."""
    for relative, digest in hashes.items():
        if not _receipt_entry_is_valid(relative, digest):
            return False
        path = root / relative
        ensure_path_within(path, root)
        if has_symlink_component(root, path) or not path.is_file():
            return False
        if portable_relpath(path, project_root) not in managed:
            return False
        if _digest(path.read_bytes()) != digest:
            return False
    return True


def _tree_is_exact(root: Path, hashes: dict[str, str]) -> bool:
    """Return whether the tree holds exactly the claimed files and their parent dirs."""
    entries = list(root.rglob("*"))
    actual = {path.relative_to(root).as_posix() for path in entries if path.is_file()}
    if actual != set(hashes) | {RECEIPT_FILENAME}:
        return False
    expected_dirs = {
        parent.as_posix()
        for relative in hashes
        for parent in Path(relative).parents
        if parent != Path(".")
    }
    for path in entries:
        if path.is_dir() and path.relative_to(root).as_posix() not in expected_dirs:
            return False
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            return False
    return True


class ExtensionIntegrator(BaseIntegrator):
    """Deploy native factories without executing code or mutating host settings."""

    @staticmethod
    def _payload(bundle: ExtensionBundle, source_plan=None) -> dict[str, bytes]:
        payload: dict[str, bytes] = {}
        for directory, dirs, files in os.walk(bundle.source_root, followlinks=False):
            base = Path(directory)
            dirs[:] = sorted(
                name
                for name in dirs
                if name not in _IGNORED_DIRS and not (base / name / RECEIPT_FILENAME).is_file()
            )
            for name in [*dirs, *files]:
                if (base / name).is_symlink():
                    raise ValueError(
                        f"Native extension resources must not be symlinks: {base / name}"
                    )
            for name in sorted(files):
                if name in (".apm-pin", RECEIPT_FILENAME):
                    continue
                source = base / name
                if not source.is_file():
                    raise ValueError(f"Native extension resource is not a regular file: {source}")
                relative = source.relative_to(bundle.source_root).as_posix()
                if source_plan is not None and not source_plan.includes(
                    portable_relpath(source, source_plan.source_root)
                ):
                    raise ValueError(f"Native extension resource is not authorized: {relative}")
                payload[relative] = source.read_bytes()
        for entry in bundle.entries:
            if entry not in payload:
                raise ValueError(
                    f"Declared native extension is absent from the deployable payload: {entry}"
                )
        # A manifest makes all designated source layouts discoverable at one
        # native package root while preserving the original relative imports.
        manifest = json.loads(payload.get("package.json", b"{}"))
        if not isinstance(manifest, dict):
            raise ValueError("Native extension package.json must be an object")
        native = manifest.get("omp", {})
        if native is None:
            native = {}
        if not isinstance(native, dict):
            raise ValueError("Native extension package.json omp must be an object")
        manifest["omp"] = {**native, "extensions": list(bundle.entries)}
        payload["package.json"] = (
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
        ).encode()
        return payload

    @staticmethod
    def _name(bundle: ExtensionBundle, package_name: str) -> str:
        identity = package_name if package_name and package_name != "_local" else bundle.name
        try:
            CanvasIntegrator._validate_canvas_name(identity)
            name = identity
        except ValueError:
            # Dependency keys include host ports, local paths and registry scopes.
            # Hash the complete key rather than using a lossy slash replacement.
            name = "package-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()
        if name in RESERVED_EXTENSION_NAMES:
            raise ValueError(
                f"Native extension package name '{name}' is reserved for the hook runtime"
            )
        return name

    @classmethod
    def render_payload(
        cls, bundle: ExtensionBundle, package_name: str = "", source_plan=None
    ) -> dict[str, bytes]:
        payload = cls._payload(bundle, source_plan)
        receipt = {
            "version": 1,
            "owner": package_name or cls._name(bundle, package_name),
            "files": {rel: _digest(data) for rel, data in payload.items()},
        }
        payload[RECEIPT_FILENAME] = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
        return payload

    @staticmethod
    def _owned(
        root: Path,
        project_root: Path,
        managed: set[str],
        *,
        owner: str | None = None,
        managed_file_hashes=None,
    ) -> dict[str, str] | None:
        receipt = root / RECEIPT_FILENAME
        if not _receipt_root_is_safe(root, receipt):
            return None
        if portable_relpath(receipt, project_root) not in managed:
            return None
        try:
            hashes = _read_receipt_hashes(receipt, project_root, owner, managed_file_hashes)
            if hashes is None:
                return None
            if not _claimed_payload_is_verified(root, project_root, managed, hashes):
                return None
            if not _tree_is_exact(root, hashes):
                return None
            return hashes
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def preflight_extensions_for_targets(
        self,
        targets,
        package_info,
        project_root,
        source_plan=None,
        *,
        package_name="",
        managed_files=None,
        managed_file_hashes=None,
        scope=None,
        is_first_party=False,
    ):
        """Validate every declared artifact and collision before any primitive writes."""
        if not any(target.supports("extensions") for target in targets):
            return
        bundles = find_extension_bundles(
            Path(package_info.install_path), is_first_party=is_first_party
        )
        from apm_cli.core.scope import InstallScope

        if bundles and is_first_party and scope is InstallScope.USER:
            raise ValueError(
                "User-scope native extensions must be installed as a tracked dependency"
            )
        managed = self.normalize_managed_files(managed_files) or set()
        for bundle in bundles:
            name = self._name(bundle, package_name)
            self._payload(bundle, source_plan)
            for target in targets:
                mapping = target.primitives.get("extensions")
                if mapping is None:
                    continue
                root = (
                    project_root / (mapping.deploy_root or target.root_dir) / mapping.subdir / name
                )
                if _has_destination_link(root):
                    raise ValueError(f"Symlinked native extension destination: {root}")
                if (
                    root.exists()
                    and self._owned(
                        root,
                        project_root,
                        managed,
                        owner=package_name or name,
                        managed_file_hashes=managed_file_hashes,
                    )
                    is None
                ):
                    raise ValueError(
                        f"Native extension destination contains foreign or modified files: {root}"
                    )
                names = _native_names(root, bundle.entries)
                reserved = names & RESERVED_EXTENSION_NAMES
                if reserved:
                    raise ValueError(
                        f"Native extension factory names are reserved for the hook runtime: {sorted(reserved)}"
                    )
                if root.parent.is_dir():
                    for sibling in root.parent.iterdir():
                        if sibling == root or sibling.name.startswith("."):
                            continue
                        if sibling.is_file() and sibling.suffix in (".ts", ".js"):
                            other_names = {sibling.stem}
                        elif sibling.is_dir():
                            from apm_cli.integration.extension_discovery import (
                                native_extension_declaration,
                            )

                            declared = native_extension_declaration(sibling)
                            if declared is None:
                                declared = [
                                    entry
                                    for entry in ("index.ts", "index.js")
                                    if (sibling / entry).is_file()
                                ][:1]
                            other_names = _native_names(sibling, tuple(declared))
                        else:
                            continue
                        if names & other_names:
                            raise ValueError(
                                f"Native extension name collision with {sibling}: {sorted(names & other_names)}"
                            )

    def integrate_extensions_for_target(
        self,
        target,
        package_info,
        project_root,
        *,
        force=False,
        managed_files=None,
        diagnostics=None,
        scope=None,
        trust_extensions=False,
        is_first_party=False,
        package_name="",
        source_plan=None,
        managed_file_hashes=None,
    ) -> IntegrationResult:
        from apm_cli.core.scope import InstallScope

        mapping = target.primitives.get("extensions")
        if mapping is None or (
            not trust_extensions and (not is_first_party or scope is InstallScope.USER)
        ):
            return IntegrationResult(0, 0, 0, [])
        self.preflight_extensions_for_targets(
            [target],
            package_info,
            project_root,
            source_plan,
            package_name=package_name,
            managed_files=managed_files,
            managed_file_hashes=managed_file_hashes,
            scope=scope,
            is_first_party=is_first_party,
        )
        paths: list[Path] = []
        integrated = adopted = 0
        for bundle in find_extension_bundles(
            Path(package_info.install_path), is_first_party=is_first_party
        ):
            name = self._name(bundle, package_name)
            root = project_root / (mapping.deploy_root or target.root_dir) / mapping.subdir / name
            payload = self.render_payload(bundle, package_name, source_plan)
            if all(
                (root / rel).is_file() and (root / rel).read_bytes() == data
                for rel, data in payload.items()
            ):
                adopted += 1
            else:
                root.parent.mkdir(parents=True, exist_ok=True)
                stage = Path(tempfile.mkdtemp(prefix=f".{name}-", dir=root.parent))
                backup = None
                try:
                    for rel, data in payload.items():
                        destination = stage / rel
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_bytes(data)
                        source = bundle.source_root / rel
                        if source.is_file() and rel != "package.json":
                            shutil.copymode(source, destination)
                    if root.exists():
                        backup = Path(tempfile.mkdtemp(prefix=f".{name}-old-", dir=root.parent))
                        backup.rmdir()
                        root.rename(backup)
                    try:
                        stage.rename(root)
                    except OSError:
                        if backup is not None:
                            backup.rename(root)
                            backup = None
                        raise
                    if backup is not None:
                        shutil.rmtree(backup)
                    integrated += 1
                finally:
                    if stage.exists():
                        shutil.rmtree(stage)
            paths.extend(root / rel for rel in payload)
        return IntegrationResult(integrated, 0, 0, paths, files_adopted=adopted)

    def sync_for_target(
        self, target, apm_package, project_root, managed_files=None, *, managed_file_hashes=None
    ) -> dict:
        """Remove only complete, hash-verified owned native bundles."""
        mapping = target.primitives.get("extensions")
        stats = {"files_removed": 0, "errors": 0, "failed_paths": []}
        if mapping is None:
            return stats
        managed = self.normalize_managed_files(managed_files) or set()
        base = project_root / (mapping.deploy_root or target.root_dir) / mapping.subdir
        roots = {project_root / rel for rel in managed if Path(rel).name == RECEIPT_FILENAME}
        for receipt in roots:
            root = receipt.parent
            if root.parent != base:
                continue
            if _has_destination_link(root):
                stats["errors"] += 1
                stats["failed_paths"].extend(
                    rel for rel in managed if (project_root / rel).is_relative_to(root)
                )
                continue
            hashes = self._owned(
                root, project_root, managed, managed_file_hashes=managed_file_hashes
            )
            if hashes is None:
                stats["errors"] += 1
                stats["failed_paths"].extend(
                    rel for rel in managed if (project_root / rel).is_relative_to(root)
                )
                continue
            try:
                shutil.rmtree(root)
                stats["files_removed"] += len(hashes) + 1
            except OSError:
                stats["errors"] += 1
                stats["failed_paths"].extend(
                    rel for rel in managed if (project_root / rel).is_relative_to(root)
                )
        return stats
