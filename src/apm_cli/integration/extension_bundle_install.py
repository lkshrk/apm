"""Validate offline native payloads before delegating atomic owned deployment."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from apm_cli.integration.base_integrator import BaseIntegrator
from apm_cli.integration.extension_discovery import find_extension_bundles, is_native_extension_path
from apm_cli.integration.extension_integrator import (
    RECEIPT_FILENAME,
    ExtensionIntegrator,
    _native_names,
)
from apm_cli.utils.content_hash import _canonical_hash_bytes, compute_file_hash
from apm_cli.utils.path_security import (
    ensure_path_within,
    has_symlink_component,
    validate_path_segments,
)
from apm_cli.utils.paths import portable_relpath


@dataclass(frozen=True)
class NativeBundlePlan:
    source_root: Path
    package_name: str
    files: tuple[str, ...]
    targets: tuple[Any, ...]
    target_paths: tuple[Path, ...]
    target_hashes: dict[Path, str]


def plan_native_bundle_files(
    bundle_dir: Path,
    pack_files: dict[str, str],
    targets: list[Any],
    project_root: Path,
    *,
    managed_files: set[str] | None = None,
    managed_file_hashes: dict[str, str] | None = None,
) -> list[NativeBundlePlan]:
    """Validate complete attested native packages and all collisions without writes."""
    native_targets = tuple(target for target in targets if target.supports("extensions"))
    if not native_targets:
        return []
    roots: dict[str, list[str]] = {}
    for relative in pack_files:
        if not is_native_extension_path(relative):
            continue
        validate_path_segments(relative, context="native bundle file")
        parts = Path(relative).parts
        index = parts.index("extensions")
        if index + 2 >= len(parts):
            raise ValueError(f"Native bundle entry is not a complete package file: {relative}")
        root = Path(*parts[: index + 2]).as_posix()
        roots.setdefault(root, []).append(relative)

    integrator = ExtensionIntegrator()
    plans: list[NativeBundlePlan] = []
    package_names: set[str] = set()
    extension_names: set[str] = set()
    for relative_root, files in sorted(roots.items()):
        source = bundle_dir / relative_root
        ensure_path_within(source, bundle_dir)
        if has_symlink_component(bundle_dir, source):
            raise ValueError(f"Symlinked native bundle root: {relative_root}")
        listed = set(files)
        actual: set[str] = set()
        for directory, directories, names in BaseIntegrator.walk_source_tree(source):
            base = Path(directory)
            for name in (*directories, *names):
                if (base / name).is_symlink():
                    raise ValueError(f"Symlinked native bundle resource: {base / name}")
            for name in names:
                path = base / name
                relative = path.relative_to(bundle_dir).as_posix()
                actual.add(relative)
                if relative not in listed:
                    raise ValueError(f"Unattested native extension resource: {relative}")
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                if digest != pack_files[relative]:
                    raise ValueError(f"Native extension resource hash mismatch: {relative}")
        if actual != listed:
            raise ValueError(f"Missing native extension resources: {sorted(listed - actual)}")
        bundles = find_extension_bundles(source)
        if not bundles:
            raise ValueError(f"Native bundle has no declared executable artifacts: {relative_root}")
        name = source.name
        owner = name
        receipt_path = source / RECEIPT_FILENAME
        if receipt_path.is_file():
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            if (
                not isinstance(receipt, dict)
                or not isinstance(receipt.get("owner"), str)
                or not receipt["owner"]
            ):
                raise ValueError(f"Invalid native bundle ownership receipt: {relative_root}")
            owner = receipt["owner"]
            if integrator._name(bundles[0], owner) != name:
                raise ValueError(
                    f"Native bundle owner does not match its deployment directory: {relative_root}"
                )
        if name in package_names:
            raise ValueError(f"Duplicate native extension package in bundle: {name}")
        package_names.add(name)
        names = set().union(*(_native_names(source, bundle.entries) for bundle in bundles))
        if names & extension_names:
            raise ValueError(
                f"Duplicate native extension names in bundle: {sorted(names & extension_names)}"
            )
        extension_names.update(names)
        integrator.preflight_extensions_for_targets(
            list(native_targets),
            SimpleNamespace(install_path=source),
            project_root,
            package_name=owner,
            managed_files=managed_files,
            managed_file_hashes=managed_file_hashes,
        )
        payload = integrator.render_payload(bundles[0], owner)
        hashes = {
            relative: "sha256:" + hashlib.sha256(_canonical_hash_bytes(data)).hexdigest()
            for relative, data in payload.items()
        }
        target_hashes = {
            project_root
            / (mapping.deploy_root or target.root_dir)
            / mapping.subdir
            / name
            / relative: digest
            for target in native_targets
            for mapping in (target.primitives["extensions"],)
            for relative, digest in hashes.items()
        }
        plans.append(
            NativeBundlePlan(
                source,
                owner,
                tuple(sorted(files)),
                native_targets,
                tuple(target_hashes),
                target_hashes,
            )
        )
    return plans


def integrate_native_bundle_plans(
    plans: list[NativeBundlePlan],
    project_root: Path,
    *,
    managed_files: set[str] | None = None,
    managed_file_hashes: dict[str, str] | None = None,
    diagnostics=None,
) -> list[Path]:
    """Install preflighted packages with receipt-backed atomic bundle ownership."""
    integrator = ExtensionIntegrator()
    paths: list[Path] = []
    for plan in plans:
        for target in plan.targets:
            result = integrator.integrate_extensions_for_target(
                target,
                SimpleNamespace(install_path=plan.source_root),
                project_root,
                package_name=plan.package_name,
                managed_files=managed_files,
                managed_file_hashes=managed_file_hashes,
                diagnostics=diagnostics,
                trust_extensions=True,
            )
            paths.extend(result.target_paths)
    return paths


def deploy_native_bundle_files(
    bundle_dir: Path,
    pack_files: dict[str, str],
    targets: list[Any],
    project_root: Path,
    *,
    dry_run: bool,
    managed_files: set[str] | None = None,
    managed_file_hashes: dict[str, str] | None = None,
    diagnostics=None,
) -> tuple[list[NativeBundlePlan], dict[str, str]]:
    """Plan native packages, drop their files from ``pack_files`` in place, and apply.

    Returns the plans plus ``{project-relative path: hash}`` for every native
    destination. ``dry_run`` reports the planned destinations and hashes
    without writing.
    """
    plans = plan_native_bundle_files(
        bundle_dir,
        pack_files,
        targets,
        project_root,
        managed_files=managed_files,
        managed_file_hashes=managed_file_hashes,
    )
    for plan in plans:
        for relative in plan.files:
            pack_files.pop(relative, None)
    if dry_run:
        native_paths = [path for plan in plans for path in plan.target_paths]
        native_hashes = {
            path: digest for plan in plans for path, digest in plan.target_hashes.items()
        }
    else:
        native_paths = integrate_native_bundle_plans(
            plans,
            project_root,
            managed_files=managed_files,
            managed_file_hashes=managed_file_hashes,
            diagnostics=diagnostics,
        )
        native_hashes = {path: compute_file_hash(path) for path in native_paths}
    return plans, {
        portable_relpath(path, project_root): native_hashes[path] for path in native_paths
    }
