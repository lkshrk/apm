"""Scratch projection helpers for audit target deployment roots."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

from apm_cli.core.scope import InstallScope, get_deploy_root, get_modules_dir
from apm_cli.integration.targets import TargetProfile
from apm_cli.utils.atomic_io import write_text_lf
from apm_cli.utils.path_security import PathTraversalError, ensure_path_within

_EXTERNAL_REPLAY_ROOT = ".apm-audit-targets"


def replay_modules_root(scratch_root: Path, *, user_scope: bool) -> Path:
    """Project the canonical scope's deployment source layout into scratch."""
    scope = InstallScope.USER if user_scope else InstallScope.PROJECT
    return scratch_root / get_modules_dir(scope).relative_to(get_deploy_root(scope))


def _project_runtime_paths(value, replacements: list[tuple[str, str]]):
    """Rewrite one JSON value using only its target's path frame."""
    if isinstance(value, str):
        for source, destination in replacements:
            value = (
                destination if value == source else value.replace(source + "/", destination + "/")
            )
        return value
    if isinstance(value, list):
        return [_project_runtime_paths(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: _project_runtime_paths(item, replacements) for key, item in value.items()}
    return value


def canonicalize_omp_hook_replay(
    scratch_root: Path,
    project_root: Path,
    targets: list[TargetProfile],
    live_targets: list[TargetProfile],
    package_roots: dict[Path, Path],
) -> None:
    """Project scratch-only runtime paths into the live frame before comparison.

    Both the descriptor and ownership sidecar are rewritten so ownership matching
    remains exact. Only scratch output changes; live handler commands and runtime
    metadata still participate in the normal owned-entry drift comparison.
    """
    live_by_replay_root = {replay_target(target).root_dir: target for target in live_targets}
    for target in targets:
        if target.name != "omp" or "hooks" not in target.primitives:
            continue
        replay_root = ensure_path_within(target.deploy_path(scratch_root), scratch_root)
        live_root = live_by_replay_root[target.root_dir].deploy_path(project_root)
        replacements = {
            str(source.resolve()): str(destination.resolve())
            for source, destination in {**package_roots, replay_root: live_root}.items()
            if source.resolve() != destination.resolve()
        }
        ordered = sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True)

        for name in ("hooks.json", "apm-hooks.json"):
            path = replay_root / name
            if path.is_file():
                document = json.loads(path.read_text(encoding="utf-8"))
                write_text_lf(
                    path, json.dumps(_project_runtime_paths(document, ordered), indent=2) + "\n"
                )


def governed_root_dirs(targets: list[TargetProfile] | None) -> set[str]:
    """Return the set of top-level managed directory names to walk.

    Includes each target's top-level ``root_dir`` (plus ``.apm``) AND every
    per-primitive ``deploy_root`` override (e.g. the ``copilot`` target routing
    ``skills`` to ``.agents``). Walking the deploy roots is what lets the drift
    differ compare committed skill bundles under ``.agents/skills/`` against the
    replay, closing the gap where deployed skill content could silently diverge
    from source (issue #1716). The replay reproduces the deploy-time link
    rewrite faithfully, so byte-identical skills do not surface as false drift.
    Only the first path segment is kept so nested deploy roots collapse to a
    single walk root.
    """
    roots: set[str] = {".apm"}
    for t in targets or []:
        root = getattr(t, "root_dir", None)
        if root:
            roots.add(str(root).split("/", 1)[0])
        primitives = getattr(t, "primitives", None) or {}
        for mapping in primitives.values():
            deploy_root = getattr(mapping, "deploy_root", None)
            if deploy_root:
                roots.add(str(deploy_root).split("/", 1)[0])
    return roots


def canvas_deploy_prefixes(targets: list[TargetProfile] | None) -> set[str]:
    """Return deployment prefixes for Copilot canvas bundles omitted by replay."""
    return _primitive_deploy_prefixes(targets, "canvas")


def extension_deploy_prefixes(targets: list[TargetProfile] | None) -> set[str]:
    """Return deployment prefixes for native extension bundles omitted by replay."""
    return _primitive_deploy_prefixes(targets, "extensions")


def _primitive_deploy_prefixes(targets: list[TargetProfile] | None, primitive: str) -> set[str]:
    prefixes: set[str] = set()
    for target in targets or []:
        mapping = getattr(target, "primitives", {}).get(primitive)
        if mapping is None:
            continue
        effective_root = mapping.deploy_root or target.root_dir
        if mapping.subdir:
            prefixes.add((Path(effective_root) / mapping.subdir).as_posix().rstrip("/") + "/")
        else:
            prefixes.add(Path(effective_root).as_posix().rstrip("/") + "/")
    return prefixes


def replay_target(target: TargetProfile) -> TargetProfile:
    """Return a scratch-contained profile for replay-only integration."""
    if target.managed_deploy_root is None:
        return target
    return replace(
        target,
        root_dir=_external_replay_relative_root(target).as_posix(),
        resolved_deploy_root=None,
    )


def external_replay_root(scratch_root: Path, target: TargetProfile) -> Path:
    """Return the scratch projection root for an external target."""
    return scratch_root / _external_replay_relative_root(target)


def _external_replay_relative_root(target: TargetProfile) -> Path:
    root = Path(_EXTERNAL_REPLAY_ROOT) / target.name
    if target.name == "omp" and target.managed_deploy_root is not None:
        # One lock can retain distinct historical native roots. Never replay
        # their independent configs into the same scratch directory.
        identity = str(target.managed_deploy_root).encode("utf-8")
        root /= hashlib.sha256(identity).hexdigest()
    return root


def replay_targets_for_owner(
    targets: list[TargetProfile],
    live_targets: list[TargetProfile],
    lockfile,
    deployment_root: Path,
    dependency_key: str,
) -> list[TargetProfile]:
    """Restrict replayed omp targets to the native roots the ledger recorded for one owner."""
    from apm_cli.integration.extension_roots import recorded_omp_roots

    owner_roots = recorded_omp_roots(lockfile, deployment_root, dependency_keys={dependency_key})
    native_live_roots = {
        replay_target(target).root_dir: target.deploy_path(deployment_root)
        for target in live_targets
        if target.name == "omp"
    }
    return [
        target
        for target in targets
        if target.name != "omp"
        or not owner_roots
        or native_live_roots[target.root_dir] in owner_roots
    ]


def omp_hook_runtime_paths(targets: list[TargetProfile]) -> set[str]:
    """Return omp hook runtime metadata paths that scratch replay never projects."""
    return {
        (Path(target.root_dir) / "apm-hooks-runtime.json").as_posix()
        for target in targets
        if target.name == "omp" and "hooks" in target.primitives
    }


def external_target_relative_roots(target: TargetProfile) -> set[str]:
    """Return bounded paths governed below an external target root."""
    roots: set[str] = set()
    for mapping in target.primitives.values():
        if mapping.deploy_root:
            deploy_root = Path(mapping.deploy_root)
            if not deploy_root.is_absolute():
                roots.add(deploy_root.parts[0])
                continue
        if mapping.subdir:
            roots.add(Path(mapping.subdir).parts[0])
        elif mapping.extension:
            roots.add(mapping.extension.lstrip("/"))
    roots.update(Path(path).parts[0] for path in target.generated_files if Path(path).parts)
    from apm_cli.install.manifest_reconcile import merge_hook_config_projection_specs

    for config, (sidecar, _container) in merge_hook_config_projection_specs(
        [replace(target, root_dir=".", resolved_deploy_root=None)]
    ).items():
        roots.update((Path(config).parts[0], Path(sidecar).parts[0]))
    if target.name == "omp" and target.supports("hooks"):
        roots.add("apm-hooks-runtime.json")
    return roots


def claims_for_root(
    claims: dict[str, str],
    root: Path,
    *,
    absolute_only: bool,
    targets: tuple[TargetProfile, ...] = (),
) -> dict[str, str]:
    """Rebase lock claims governed by *root* into comparison-relative paths."""
    root = root.resolve()
    rebased: dict[str, str] = {}
    for path, owner in claims.items():
        candidate = Path(path)
        if candidate.is_absolute():
            try:
                validated = ensure_path_within(candidate, root)
                relative = validated.relative_to(root)
            except (PathTraversalError, ValueError):
                continue
            rebased[relative.as_posix()] = owner
        elif absolute_only:
            for target in targets:
                try:
                    decoded = target.decode_external_locator(path, root)
                except (PathTraversalError, ValueError):
                    continue
                if decoded is None:
                    continue
                validated = ensure_path_within(decoded, root)
                rebased[validated.relative_to(root).as_posix()] = owner
                break
        elif not absolute_only:
            rebased[path] = owner
    return rebased
