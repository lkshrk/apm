"""Owned omp hook bridge deployment and read-only preflight."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from importlib.resources import files
from pathlib import Path

from apm_cli.adapters.client.omp import OmpClientAdapter
from apm_cli.hook_contract import HookContractError
from apm_cli.integration.hook_ownership import (
    extract_apm_source_sidecar,
    reinject_apm_source_from_sidecar,
)
from apm_cli.integration.omp_hook_contract import omp_package_files, render_omp_hooks
from apm_cli.integration.omp_hook_namespace import preflight_omp_hook_namespace
from apm_cli.utils.atomic_io import atomic_write_text
from apm_cli.utils.content_hash import compute_file_hash
from apm_cli.utils.path_security import has_symlink_component

OMP_HOOK_BRIDGES = {
    "project": "extensions/apm-hooks-project/index.ts",
    "user": "extensions/apm-hooks-user/index.ts",
}
OMP_HOOK_RUNTIME_STATE = "apm-hooks-runtime.json"


def omp_hook_bridge_path(user_scope: bool = False) -> str:
    """Return a stable native module name distinct from the other install scope."""
    return OMP_HOOK_BRIDGES["user" if user_scope else "project"]


def _safe_path(path: Path) -> None:
    if has_symlink_component(Path(path.anchor), path):
        raise HookContractError(f"omp hook artifact must not traverse a symlink: {path}")


def _read_object(path: Path) -> dict:
    _safe_path(path)
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HookContractError(f"cannot read omp hook artifact: {path}") from exc
    if not isinstance(value, dict):
        raise HookContractError(f"omp hook artifact must be an object: {path}")
    return value


def _existing(target_dir: Path) -> tuple[dict, dict, dict]:
    config = _read_object(target_dir / "hooks.json")
    sidecar = _read_object(target_dir / "apm-hooks.json")
    state = _read_object(target_dir / OMP_HOOK_RUNTIME_STATE)
    hooks = config.get("hooks", {})
    if not isinstance(hooks, dict) or any(
        not isinstance(entries, list) for entries in hooks.values()
    ):
        raise HookContractError("existing omp hook config requires event arrays")
    if (target_dir / "apm-hooks.json").exists() and not sidecar:
        raise HookContractError("omp hook ownership sidecar is foreign or empty")
    if any(
        not isinstance(entries, list)
        or not entries
        or any(
            not isinstance(entry, dict)
            or not isinstance(entry.get("_apm_source"), str)
            or not entry["_apm_source"]
            for entry in entries
        )
        for entries in sidecar.values()
    ):
        raise HookContractError("invalid omp hook ownership sidecar")
    if any(
        isinstance(entry, dict) and "_apm_source" in entry
        for entries in hooks.values()
        for entry in entries
    ):
        raise HookContractError("native omp hook ownership must come from the sidecar")
    reinject_apm_source_from_sidecar(hooks, sidecar)
    return config, sidecar, state


def _runtime_owners(hooks: dict) -> set[str]:
    owners = set()
    for entries in hooks.values():
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                continue
            for handler in entry["hooks"]:
                if isinstance(handler, dict) and isinstance(handler.get("apm"), dict):
                    owner = handler["apm"].get("owner")
                    if isinstance(owner, str):
                        owners.add(owner)
    return owners


def _check_bridge(target_dir: Path, state: dict, *, user_scope: bool | None = None) -> Path:
    if state and (
        set(state) != {"scope", "bridgeHash", "configCreated"}
        or not isinstance(state.get("scope"), str)
        or state["scope"] not in OMP_HOOK_BRIDGES
        or type(state.get("configCreated")) is not bool
        or not isinstance(state.get("bridgeHash"), str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", state["bridgeHash"])
    ):
        raise HookContractError("invalid omp hook runtime ownership metadata")
    scope = state.get("scope") if user_scope is None else ("user" if user_scope else "project")
    if scope not in OMP_HOOK_BRIDGES or (state and state["scope"] != scope):
        raise HookContractError("omp hook runtime scope conflicts with its configuration root")
    bridge = target_dir / OMP_HOOK_BRIDGES[scope]
    _safe_path(bridge)
    if any(
        (target_dir / path).exists() or (target_dir / path).is_symlink()
        for other_scope, path in OMP_HOOK_BRIDGES.items()
        if other_scope != scope
    ):
        raise HookContractError("omp configuration root contains conflicting hook bridge scopes")
    if bridge.parent.exists():
        if not bridge.parent.is_dir() or any(path != bridge for path in bridge.parent.iterdir()):
            raise HookContractError("omp hook bridge directory contains unrelated content")
    if bridge.exists() and (
        not state or not bridge.is_file() or compute_file_hash(bridge) != state.get("bridgeHash")
    ):
        raise HookContractError("omp hook bridge is foreign or edited; refusing to overwrite")
    if (target_dir / OMP_HOOK_RUNTIME_STATE).exists() and not state:
        raise HookContractError("omp hook runtime ownership file is foreign")
    return bridge


def _verify_owned_namespace_bridge(target_dir: Path, scope: str) -> None:
    state = _read_object(target_dir / OMP_HOOK_RUNTIME_STATE)
    _check_bridge(target_dir, state, user_scope=scope == "user")


def preflight_omp_hooks(
    integrator,
    package_info,
    project_root: Path,
    selection,
    *,
    user_scope: bool = False,
    target=None,
) -> tuple[Path, list[tuple[Path, dict]]]:
    """Validate every selected descriptor, runtime context and destination before writes."""
    target_dir = (
        target.deploy_path(project_root)
        if target is not None
        else OmpClientAdapter.config_path_for(project_root, user_scope).parent
    ).absolute()
    descriptors = selection.descriptors_for("omp")
    if not descriptors:
        return target_dir, []
    package_root = Path(package_info.install_path).absolute()
    from apm_cli.integration.extension_discovery import find_extension_bundles

    is_first_party = selection.is_first_party or integrator._is_root_local_package(
        package_info, project_root
    )
    if find_extension_bundles(package_root, is_first_party=is_first_party):
        raise HookContractError("omp hook source plan conflicts with native extensions")
    if is_first_party:
        for source in selection.files:
            if has_symlink_component(package_root, source.absolute()) or not source.is_file():
                raise HookContractError(
                    f"omp first-party hook asset is missing or unsafe: {source}"
                )
    elif not omp_package_files(package_root) <= selection.files:
        raise HookContractError("omp hook runtime context changed after source authorization")
    config, sidecar, state = _existing(target_dir)
    _check_bridge(target_dir, state, user_scope=user_scope)
    preflight_omp_hook_namespace(
        target_dir,
        project_root,
        user_scope=user_scope,
        bridge_paths=OMP_HOOK_BRIDGES,
        verify_owned_bridge=_verify_owned_namespace_bridge,
    )
    name = integrator._get_package_name(package_info, project_root)
    owner, legacy = integrator._get_hook_source_markers(package_info, project_root, name)
    owners = {owner, *legacy}
    expected = Counter(
        entry.get("_apm_source")
        for entries in sidecar.values()
        for entry in entries
        if isinstance(entry, dict) and entry.get("_apm_source") in owners
    )
    actual = Counter(
        entry.get("_apm_source")
        for entries in config.get("hooks", {}).values()
        for entry in entries
        if isinstance(entry, dict) and entry.get("_apm_source") in owners
    )
    if expected != actual:
        raise HookContractError(
            "owned omp hook entries were changed or removed; refusing duplicate activation"
        )
    for entries in config.get("hooks", {}).values():
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                continue
            tagged = any(
                isinstance(handler, dict) and "apm" in handler for handler in entry["hooks"]
            )
            if tagged and "_apm_source" not in entry:
                raise HookContractError(
                    "omp descriptor contains unowned or edited runtime metadata"
                )
    data_dir = target_dir / "hook-data" / hashlib.sha256(owner.encode()).hexdigest()[:20]
    _safe_path(data_dir)
    rendered = []
    for descriptor in descriptors:
        data = integrator._parse_hook_json(descriptor)
        if data is None:
            raise HookContractError(f"invalid omp hook descriptor: {descriptor}")
        payload = render_omp_hooks(
            data,
            package_root=package_root,
            source_dir=descriptor.parent.absolute(),
            owner=owner,
            data_dir=data_dir,
        )
        if payload["hooks"]:
            rendered.append((descriptor, payload))
    # Resource failures are preflight failures, never partially deployed hooks.
    files("apm_cli.integration").joinpath("omp_hook_runtime.ts").read_text(encoding="utf-8")
    return target_dir, rendered


def integrate_omp_hooks(
    integrator,
    package_info,
    project_root: Path,
    *,
    target,
    source_plan=None,
    user_scope: bool = False,
):
    """Merge owned entries and deploy one shared bridge, preserving all foreign content."""
    from apm_cli.integration.hook_integrator import HookIntegrationResult

    selection = integrator.select_hook_sources_for_target(
        package_info,
        "omp",
        source_plan=source_plan,
        is_first_party=integrator._is_root_local_package(package_info, project_root),
    )
    target_dir, rendered = preflight_omp_hooks(
        integrator, package_info, project_root, selection, user_scope=user_scope, target=target
    )
    name = integrator._get_package_name(package_info, project_root)
    owner, legacy = integrator._get_hook_source_markers(package_info, project_root, name)
    owners = {owner, *legacy}
    if not rendered:
        stats = {"files_removed": 0, "errors": 0}
        clean_omp_hooks(target_dir, stats, source_markers=frozenset(owners))
        if stats["errors"]:
            raise HookContractError("cannot remove prior omp hooks: owned artifacts require review")
        return HookIntegrationResult(
            files_integrated=0, files_updated=0, files_skipped=0, target_paths=[]
        )
    config, _sidecar, state = _existing(target_dir)
    config_created = state.get("configCreated", not (target_dir / "hooks.json").exists())
    hooks = config.setdefault("hooks", {})
    for event in list(hooks):
        hooks[event] = [
            entry
            for entry in hooks[event]
            if not isinstance(entry, dict) or entry.get("_apm_source") not in owners
        ]
        if not hooks[event]:
            del hooks[event]
    for _descriptor, payload in rendered:
        for event, entries in payload["hooks"].items():
            for entry in entries:
                entry["_apm_source"] = owner
                if entry not in hooks.setdefault(event, []):
                    hooks[event].append(entry)
    sidecar = extract_apm_source_sidecar(hooks)
    for _descriptor, payload in rendered:
        for entries in payload["hooks"].values():
            for entry in entries:
                entry.pop("_apm_source", None)
    display = [
        integrator._build_display_payload("omp hooks", "hooks.json", descriptor, payload)
        for descriptor, payload in rendered
    ]
    bridge = target_dir / omp_hook_bridge_path(user_scope)
    runtime = (
        files("apm_cli.integration").joinpath("omp_hook_runtime.ts").read_text(encoding="utf-8")
    )
    bridge.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(bridge, runtime)
    state = {
        "scope": "user" if user_scope else "project",
        "bridgeHash": compute_file_hash(bridge),
        "configCreated": config_created,
    }
    atomic_write_text(target_dir / OMP_HOOK_RUNTIME_STATE, json.dumps(state, indent=2) + "\n")
    atomic_write_text(target_dir / "apm-hooks.json", json.dumps(sidecar, indent=2) + "\n")
    atomic_write_text(target_dir / "hooks.json", json.dumps(config, indent=2) + "\n")
    return HookIntegrationResult(
        files_integrated=len(rendered),
        files_updated=0,
        files_skipped=0,
        target_paths=[bridge, target_dir / OMP_HOOK_RUNTIME_STATE],
        display_payloads=display,
    )


def cleanup_omp_hook_runtime(target_dir: Path, stats: dict) -> None:
    """Remove only unchanged owned runtime artifacts after the final managed hook."""
    try:
        config, _sidecar, state = _existing(target_dir)
        if not state:
            return
        # Edited handlers with runtime metadata still need their bridge. Foreign
        # entries without APM context are deliberately ignored by the runtime.
        if _runtime_owners(config.get("hooks", {})):
            return
        bridge = _check_bridge(target_dir, state)
        if bridge.exists():
            bridge.unlink()
            stats["files_removed"] += 1
        if bridge.parent.is_dir() and not any(bridge.parent.iterdir()):
            bridge.parent.rmdir()
        config_path = target_dir / "hooks.json"
        if (
            state["configCreated"]
            and not config.keys() - {"hooks"}
            and not any(config.get("hooks", {}).values())
            and config_path.exists()
        ):
            config_path.unlink()
            stats["files_removed"] += 1
        (target_dir / OMP_HOOK_RUNTIME_STATE).unlink()
        stats["files_removed"] += 1
    except (OSError, ValueError) as exc:
        stats["errors"] = stats.get("errors", 0) + 1
        stats.setdefault("failed_paths", []).append(str(target_dir / OMP_HOOK_RUNTIME_STATE))
        stats.setdefault("messages", []).append(str(exc))


def clean_omp_hooks(
    target_dir: Path, stats: dict, *, source_markers: frozenset[str] | None = None
) -> None:
    """Reconcile matching owned entries before removing the shared runtime."""
    if (
        not (target_dir / "apm-hooks.json").exists()
        and not (target_dir / OMP_HOOK_RUNTIME_STATE).exists()
    ):
        return
    try:
        config, sidecar, _state = _existing(target_dir)
        if _state:
            _check_bridge(target_dir, _state)
        hooks = config.get("hooks", {})
        changed = False
        for event in list(hooks):
            entries = hooks[event]
            kept = [
                entry
                for entry in entries
                if not (
                    isinstance(entry, dict)
                    and "_apm_source" in entry
                    and (source_markers is None or entry["_apm_source"] in source_markers)
                )
            ]
            if len(kept) != len(entries):
                changed = True
            if kept:
                hooks[event] = kept
            else:
                hooks.pop(event)
        if not hooks:
            config.pop("hooks", None)
        sidecar_out = extract_apm_source_sidecar(hooks)
        # Keep ownership evidence for edited handlers instead of claiming their
        # uninstall succeeded or activating another copy on a later install.
        live_owners = _runtime_owners(hooks)
        for event, entries in sidecar.items():
            matched = Counter(
                json.dumps(entry, sort_keys=True) for entry in sidecar_out.get(event, [])
            )
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                owner = entry.get("_apm_source")
                removing = source_markers is None or owner in source_markers
                if not removing:
                    key = json.dumps(entry, sort_keys=True)
                    if matched[key]:
                        matched[key] -= 1
                    else:
                        sidecar_out.setdefault(event, []).append(entry)
                    continue
                if removing and owner in live_owners:
                    sidecar_out.setdefault(event, []).append(entry)
                    stats["errors"] = stats.get("errors", 0) + 1
                    stats.setdefault("failed_paths", []).append(str(target_dir / "hooks.json"))
        if changed:
            atomic_write_text(target_dir / "hooks.json", json.dumps(config, indent=2) + "\n")
            stats["files_removed"] += 1
        sidecar_path = target_dir / "apm-hooks.json"
        if sidecar_out:
            atomic_write_text(sidecar_path, json.dumps(sidecar_out, indent=2) + "\n")
        elif sidecar_path.exists():
            sidecar_path.unlink()
            stats["files_removed"] += 1
        cleanup_omp_hook_runtime(target_dir, stats)
    except (OSError, ValueError) as exc:
        stats["errors"] = stats.get("errors", 0) + 1
        stats.setdefault("failed_paths", []).append(str(target_dir / "hooks.json"))
        stats.setdefault("messages", []).append(str(exc))


def clean_historical_omp_hooks(
    lockfile, project_root: Path, stats: dict, *, user_scope: bool = False
) -> None:
    """Clean owned hooks at ledger-recorded omp roots other than the current native root."""
    from apm_cli.integration.extension_roots import recorded_omp_roots
    from apm_cli.integration.targets import KNOWN_TARGETS

    current = KNOWN_TARGETS["omp"].for_scope(user_scope=user_scope)
    current_root = current.deploy_path(project_root) if current is not None else None
    for root in recorded_omp_roots(lockfile, project_root):
        if root != current_root:
            clean_omp_hooks(root, stats)


def reconcile_removed_omp_owners(
    project_root: Path,
    source_markers: set[str],
    *,
    user_scope: bool = False,
    native_roots=(),
) -> dict:
    """Reconcile removed owners without contracting surviving package targets."""
    stats = {"files_removed": 0, "errors": 0}
    if not source_markers:
        return stats
    recorded_roots = {Path(root).absolute() for root in native_roots}
    roots = {
        (project_root / (".omp/agent" if user_scope else ".omp")).absolute(),
        OmpClientAdapter.config_path_for(project_root, user_scope).parent.absolute(),
        *recorded_roots,
    }
    for root in sorted(roots):
        if not (root / "apm-hooks.json").exists() and not (root / OMP_HOOK_RUNTIME_STATE).exists():
            continue
        try:
            config, sidecar, _state = _existing(root)
            recorded_owners = {
                entry["_apm_source"] for entries in sidecar.values() for entry in entries
            }
            live_owners = _runtime_owners(config.get("hooks", {}))
            if source_markers & (live_owners - recorded_owners):
                raise HookContractError("removed omp hook owner has no matching ownership sidecar")
            if not source_markers & (recorded_owners | live_owners):
                # A ledger-proven removed-owner root may retain an orphaned
                # bridge after its descriptor disappeared; never touch others.
                if root not in recorded_roots or recorded_owners or live_owners:
                    continue
            clean_omp_hooks(root, stats, source_markers=frozenset(source_markers))
        except (OSError, ValueError) as exc:
            stats["errors"] += 1
            stats.setdefault("failed_paths", []).append(str(root / "hooks.json"))
            stats.setdefault("messages", []).append(str(exc))
    return stats
