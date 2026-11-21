"""Retire removed owners' native hooks before releasing their lock claims."""

from __future__ import annotations

from pathlib import Path

from apm_cli.integration.extension_roots import recorded_omp_roots
from apm_cli.integration.hook_integrator import HookIntegrator
from apm_cli.integration.hook_ownership import dependency_hook_source_marker
from apm_cli.models.dependency.materialization import materialization_relative_path


def reconcile_removed_native_hook_owners(
    lockfile,
    dependency_keys: set[str],
    project_root: Path,
    *,
    user_scope: bool = False,
) -> dict[str, int]:
    """Clean only removed package owners, including previously selected omp roots.

    The complete pre-removal lock supplies canonical markers and disambiguates
    legacy basename markers. Current manifest target restrictions must not hide
    an old deployment, nor authorize wiping a surviving package's shared hooks.

    Identities come from the pure materialization path, never from
    ``apm_modules``: preserved sources may be unsafe symlinks that must not be
    resolved. A lock entry whose identity cannot be derived retains its own
    claim and makes every legacy basename alias ambiguous, so only canonical
    markers are cleaned then.
    """
    if lockfile is None or not dependency_keys:
        return {"files_removed": 0, "errors": 0}
    by_leaf: dict[str, set[str]] = {}
    identities: dict[str, tuple[str, str]] = {}
    aliases_ambiguous = False
    for dependency in lockfile.get_package_dependencies():
        try:
            reference = dependency.to_dependency_ref()
            marker = dependency_hook_source_marker(reference)
            leaf = materialization_relative_path(reference).name
        except ValueError:
            aliases_ambiguous = True
            continue
        by_leaf.setdefault(leaf, set()).add(marker)
        identities[dependency.get_unique_key()] = (marker, leaf)
    markers: set[str] = set()
    for key in dependency_keys:
        identity = identities.get(key)
        if identity is None:
            continue
        marker, leaf = identity
        markers.add(marker)
        if not aliases_ambiguous and len(by_leaf[leaf]) == 1:
            markers.add(leaf)
    if not markers:
        return {"files_removed": 0, "errors": 0}

    native_roots = recorded_omp_roots(lockfile, project_root, dependency_keys=dependency_keys)
    return HookIntegrator().reconcile_removed_owner_targets(
        project_root,
        markers,
        user_scope=user_scope,
        native_roots=native_roots,
    )
