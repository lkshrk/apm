"""Deterministic native-state import protocol."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import unquote, urlsplit

from apm_cli.factory import ClientFactory
from apm_cli.install.locking import lifecycle_operation
from apm_cli.integration.targets import KNOWN_TARGETS
from apm_cli.utils.atomic_io import atomic_write_text
from apm_cli.utils.content_hash import compute_file_hash
from apm_cli.utils.yaml_io import dump_yaml_roundtrip, load_yaml, yaml_to_str

from . import candidate_discovery as _candidate_discovery
from .candidate_discovery import (
    ImportProtocolError,
    _candidate_set_identity,
    _canonical,
    _canonical_project_root,
    _digest,
    _discover_special_targets,
    _discover_target_extras,
    _discover_unmanaged_clients,
    _exclusion_entry,
    _exclusion_matches,
    _file_hash,
    _load_exclusions,
    _load_structured,
    _ownership_path_key,
    _preimage,
    _sanitize,
    _scope_identity,
    _tree_entries,
    _write_exclusions,
)
from .discovery import discover_filesystem_resources, path_boundary_error
from .journal import allow_operation, journal_root, read_journal, write_journal
from .mcp_discovery import discover_mcp_sources
from .plugin_discovery import capture_activation, discover_plugin_state
from .secure import SecureRoot, harden_path, restore_file_bytes

_Root = _candidate_discovery._Root
_candidate = _candidate_discovery._candidate

SCHEMA_VERSION = 1
COORDINATORS = frozenset({"standalone", "omni-v24"})
KINDS = frozenset(
    {
        "instruction",
        "agent",
        "command",
        "skill",
        "hook",
        "plugin",
        "marketplace",
        "mcp",
        "package",
        "unsupported",
    }
)
CLASSIFICATIONS = frozenset(
    {
        "already-managed",
        "duplicate",
        "importable",
        "local-package",
        "needs-choice",
        "conflict",
        "secret-blocked",
        "unsupported",
        "excluded",
    }
)
_EMPTY_RESOLUTION = {
    "decision": "",
    "selected_origin_id": "",
    "approved_targets": [],
    "env_bindings": {},
    "approved_executables": [],
}


def _discover_filesystem_targets(
    targets: tuple[str, ...] | list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return _candidate_discovery._discover_filesystem_targets(
        targets, discover_resources=discover_filesystem_resources
    )


def _discover_plugins(
    targets: tuple[str, ...] | list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return _candidate_discovery._discover_plugins(targets, discover_state=discover_plugin_state)


def _discover_mcp_targets(
    targets: tuple[str, ...] | list[str],
    *,
    project_root: Path | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return _candidate_discovery._discover_mcp_targets(
        targets,
        project_root=project_root,
        discover_sources=discover_mcp_sources,
    )


def _discover_targets(
    targets: tuple[str, ...] | list[str],
    *,
    project_root: Path | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    normalized = set(targets)
    supported = set(KNOWN_TARGETS) | set(ClientFactory.supported_clients())
    unknown = sorted(normalized - supported)
    if unknown:
        raise ImportProtocolError(f"unsupported source target: {', '.join(unknown)}")
    if project_root is not None:
        return _discover_mcp_targets(sorted(normalized), project_root=project_root)
    native_targets = sorted(normalized & set(KNOWN_TARGETS))
    candidates, preimages = _discover_filesystem_targets(native_targets)
    special_candidates, special_preimages = _discover_special_targets(native_targets)
    candidates.extend(special_candidates)
    preimages.extend(special_preimages)
    mcp_candidates, mcp_preimages = _discover_mcp_targets(
        sorted(normalized), project_root=project_root
    )
    candidates.extend(mcp_candidates)
    preimages.extend(mcp_preimages)
    plugin_candidates, plugin_preimages = _discover_plugins(native_targets)
    candidates.extend(plugin_candidates)
    preimages.extend(plugin_preimages)
    for target in native_targets:
        extra_candidates, extra_preimages = _discover_target_extras(target)
        candidates.extend(extra_candidates)
        preimages.extend(extra_preimages)
    return candidates, preimages


def _discover_target(target: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Compatibility wrapper for callers scanning one native target."""
    return _discover_targets([target])


def _managed_ids(candidate_data: dict[str, Any]) -> set[str]:
    scope, project_root = _scope_identity(candidate_data)
    if scope == "project":
        from apm_cli.deps.lockfile import LockFile, get_lockfile_path

        lock = LockFile.read(get_lockfile_path(project_root))
        if lock is None:
            return set()
        manifest = (
            load_yaml(project_root / "apm.yml") if (project_root / "apm.yml").is_file() else {}
        )
        declared = {
            item.get("name")
            for item in (
                manifest.get("dependencies", {}).get("mcp", [])
                if isinstance(manifest, dict)
                else []
            )
            if isinstance(item, dict)
        }
        managed: set[str] = set()
        for candidate in candidate_data["candidates"]:
            if candidate["kind"] != "mcp":
                continue
            locked = lock.mcp_configs.get(candidate["name"])
            owned = candidate["name"] in declared
            if (
                owned
                and isinstance(locked, dict)
                and all(locked.get(key) == value for key, value in candidate["payload"].items())
            ):
                managed.add(candidate["id"])
        return managed
    from apm_cli.deps.lockfile import LockFile

    lock = LockFile.read(Path.home() / ".apm" / "apm.lock.yaml")
    result: set[str] = set()
    if lock is not None:
        manifest_path = Path.home() / ".apm" / "apm.yml"
        manifest = load_yaml(manifest_path) if manifest_path.is_file() else {}
        declared_mcp = {
            item.get("name")
            for item in (
                manifest.get("dependencies", {}).get("mcp", [])
                if isinstance(manifest, dict)
                else []
            )
            if isinstance(item, dict)
        }
        claims: dict[str, str] = {}

        def add_claims(paths: list[str], hashes: dict[str, str]) -> None:
            normalized_hashes = {
                _ownership_path_key(raw): value.removeprefix("sha256:")
                for raw, value in hashes.items()
                if "://" not in raw
            }
            for raw in paths:
                if "://" in raw:
                    continue
                key = _ownership_path_key(raw)
                if key in normalized_hashes:
                    claims[key] = normalized_hashes[key]

        add_claims(lock.local_deployed_files, lock.local_deployed_file_hashes)
        for dependency in lock.dependencies.values():
            add_claims(dependency.deployed_files, dependency.deployed_file_hashes)

        preimages = {item["id"]: item for item in candidate_data["source_preimages"]}

        def preimage_is_claimed(preimage: dict[str, Any]) -> bool:
            path = Path(preimage["absolute_path"])
            if preimage["kind"] == "file":
                if path_boundary_error(path.parent, path):
                    return False
                return claims.get(_ownership_path_key(path)) == compute_file_hash(
                    path
                ).removeprefix("sha256:")
            files = sorted(item for item in path.rglob("*") if item.is_file())
            return bool(files) and all(
                path_boundary_error(path, item) is None
                and claims.get(_ownership_path_key(item))
                == compute_file_hash(item).removeprefix("sha256:")
                for item in files
            )

        for candidate in candidate_data["candidates"]:
            if candidate["kind"] == "mcp":
                locked = lock.mcp_configs.get(candidate["name"])
                if (
                    candidate["name"] in declared_mcp
                    and isinstance(locked, dict)
                    and all(locked.get(key) == value for key, value in candidate["payload"].items())
                ):
                    result.add(candidate["id"])
                continue
            source_preimages = [
                preimages[source_id]
                for source_id in candidate["source_preimage_ids"]
                if source_id in preimages
            ]
            if source_preimages and all(preimage_is_claimed(item) for item in source_preimages):
                result.add(candidate["id"])
    root = Path.home() / ".apm" / "imported"
    if not root.is_dir():
        return result
    for metadata in root.glob("*/*/.apm-import.json"):
        try:
            result.update(json.loads(metadata.read_text(encoding="utf-8")).get("candidate_ids", []))
        except (OSError, ValueError, TypeError) as exc:
            raise ImportProtocolError(f"malformed imported ownership metadata: {metadata}") from exc
    return result


def _validate_candidate_envelope(data: Any) -> dict[str, Any]:
    required = {
        "schema_version",
        "coordinator",
        "sources",
        "candidate_set_id",
        "source_preimages",
        "candidates",
    }
    optional = {"scope", "project_root"}
    if not isinstance(data, dict) or not required.issubset(data) or set(data) - required - optional:
        raise ImportProtocolError(f"candidate schema fields mismatch: expected {sorted(required)}")
    if data["schema_version"] != SCHEMA_VERSION or data["coordinator"] not in COORDINATORS:
        raise ImportProtocolError("unsupported candidate schema/coordinator")
    scope, project_root = _scope_identity(data)
    candidate_required = {
        "id",
        "kind",
        "name",
        "root_id",
        "source_handle",
        "source_target",
        "provenance",
        "payload",
        "content_fingerprint",
        "source_preimage_ids",
        "executable_paths",
    }
    for candidate in data["candidates"]:
        extras = set(candidate) - candidate_required - {"secret_blocked"}
        missing = candidate_required - set(candidate)
        if (
            extras
            or missing
            or candidate["kind"] not in KINDS
            or not isinstance(candidate["source_target"], list)
        ):
            raise ImportProtocolError(
                f"invalid candidate {candidate.get('id', '<unknown>')}: missing={sorted(missing)} extra={sorted(extras)}"
            )
    if scope == "project":
        for preimage in data["source_preimages"]:
            path = Path(preimage.get("absolute_path", ""))
            if (
                not path.is_absolute()
                or path_boundary_error(project_root, path) is not None
                or not path.is_relative_to(project_root)
            ):
                raise ImportProtocolError("project MCP preimage escapes the selected workspace")
        if any(
            candidate["kind"] not in {"mcp", "unsupported"}
            or len(candidate["source_target"]) != 1
            or candidate["source_target"][0] not in data["sources"]
            for candidate in data["candidates"]
        ):
            raise ImportProtocolError("project import candidate set mixed scopes or targets")
    expected = _candidate_set_identity(data)
    if not hmac.compare_digest(str(data["candidate_set_id"]), expected):
        raise ImportProtocolError("candidate_set_id does not match candidate content")
    return data


def _validate_preimages(data: dict[str, Any]) -> None:
    unmanaged_preimages = {
        preimage_id
        for candidate in data["candidates"]
        if candidate.get("provenance") == "native-unmanaged"
        for preimage_id in candidate["source_preimage_ids"]
    }
    for expected in data["source_preimages"]:
        path = Path(expected["absolute_path"])
        if not path.is_absolute():
            raise ImportProtocolError("source preimage path must be absolute")
        if expected["id"] in unmanaged_preimages:
            if not path.exists() or path.is_symlink():
                raise ImportProtocolError(f"stale unmanaged client root: {path}")
            continue
        current = _preimage(path)
        for field in ("id", "kind", "size", "mode", "content_fingerprint"):
            if current[field] != expected[field]:
                raise ImportProtocolError(f"stale source preimage: {path}")


def _write_json(path: Path, data: dict[str, Any]) -> None:
    if not path.is_absolute():
        raise ImportProtocolError("protocol output paths must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        path.parent.chmod(0o700)
    if path.is_symlink():
        raise ImportProtocolError(f"refusing symlink output: {path}")
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n", new_file_mode=0o600)
    harden_path(path)


def _validate_protocol_file(path: Path) -> None:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ImportProtocolError(f"protocol file must be an absolute regular file: {path}")
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ImportProtocolError(f"protocol file is not owner-only: {path}")


def _apm_state_fingerprint(candidate_data: dict[str, Any]) -> str:
    scope, project_root = _scope_identity(candidate_data)
    if scope == "project":
        paths = [project_root / "apm.yml", project_root / "apm.lock.yaml"]
    else:
        paths = [
            Path.home() / ".apm" / "apm.yml",
            Path.home() / ".apm" / "apm.lock.yaml",
            Path.home() / ".apm" / "marketplaces.json",
            Path.home() / ".apm" / "import-exclusions.yml",
        ]
        imported = Path.home() / ".apm" / "imported"
        if imported.is_dir():
            paths.extend(sorted(imported.glob("*/*/.apm-import.json")))
    state = []
    for path in paths:
        if path.is_symlink():
            raise ImportProtocolError(f"APM ownership state is a symlink: {path}")
        state.append(
            {
                "path": str(path),
                "exists": path.is_file(),
                "hash": _file_hash(path) if path.is_file() else None,
            }
        )
    return _digest(state)


def _plan(
    candidate_data: dict[str, Any], resolutions: dict[str, dict[str, Any]] | None = None
) -> dict[str, Any]:
    scope, project_root = _scope_identity(candidate_data)
    exclusions = _load_exclusions() if scope == "global" else {}
    managed = _managed_ids(candidate_data)
    name_fingerprints: dict[tuple[str, str], set[str]] = {}
    name_candidates: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for candidate in candidate_data["candidates"]:
        if candidate.get("payload", {}).get("unsupported_reason"):
            continue
        name_key = (candidate["kind"], candidate["name"])
        name_fingerprints.setdefault(name_key, set()).add(candidate["content_fingerprint"])
        name_candidates.setdefault(name_key, []).append(candidate)
    seen: set[tuple[str, str, str]] = set()
    grouped: set[str] = set()
    items = []
    blockers = []
    for candidate in sorted(candidate_data["candidates"], key=lambda value: value["id"]):
        name_key = (candidate["kind"], candidate["name"])
        if len(name_fingerprints.get(name_key, set())) > 1:
            origins = sorted(name_candidates[name_key], key=lambda value: value["id"])
            if candidate["id"] in grouped:
                continue
            candidate_ids = [origin["id"] for origin in origins]
            grouped.update(candidate_ids)
            targets = sorted({target for origin in origins for target in origin["source_target"]})
            action = "block"
            item_id = _digest({"candidates": candidate_ids, "action": action})[:32]
            reasons = ["non-equivalent-name-collision"]
            item = {
                "id": item_id,
                "candidate_ids": candidate_ids,
                "kind": candidate["kind"],
                "name": candidate["name"],
                "classification": "conflict",
                "proposed_action": action,
                "current_targets": targets,
                "proposed_targets": targets,
                "proposed_destination": f"imported:{candidate['kind']}:{candidate['name']}",
                "reason_codes": reasons,
                "resolution": dict((resolutions or {}).get(item_id, _EMPTY_RESOLUTION)),
            }
            items.append(item)
            blockers.append({"item_id": item_id, "reason_codes": reasons})
            continue
        key = (candidate["kind"], candidate["name"], candidate["content_fingerprint"])
        if candidate.get("payload", {}).get("disposition") == "excluded":
            classification, action, reasons = "excluded", "retain", ["legacy-negative-state"]
        elif candidate["id"] in exclusions:
            excluded = exclusions[candidate["id"]]
            if _exclusion_matches(excluded, candidate, candidate["source_target"]):
                classification, action, reasons = "excluded", "retain", ["durable-exclusion"]
            else:
                classification, action, reasons = "needs-choice", "block", ["excluded-changed"]
        elif (
            candidate.get("payload", {}).get("target_resolution_required") is True
            and candidate.get("payload", {}).get("unsupported_reason") == "conditional-group-host"
        ):
            classification, action, reasons = "needs-choice", "block", ["conditional-group-host"]
        elif candidate.get("payload", {}).get("target_resolution_required") is True:
            classification, action, reasons = "needs-choice", "block", ["legacy-unscoped-targets"]
        elif candidate.get("payload", {}).get("unsupported_reason"):
            classification, action, reasons = (
                "unsupported",
                "retain",
                [str(candidate["payload"]["unsupported_reason"])],
            )
        elif candidate["id"] in managed:
            classification, action, reasons = (
                "already-managed",
                "reuse",
                ["managed-import-metadata"],
            )
        elif candidate["executable_paths"]:
            classification, action, reasons = (
                "needs-choice",
                "snapshot",
                [
                    "executable-approval-required",
                    *(f"executable:{path}" for path in sorted(candidate["executable_paths"])),
                ],
            )
        elif candidate.get("secret_blocked") or _contains_blocked(candidate["payload"]):
            classification, action, reasons = (
                "secret-blocked",
                "block",
                [
                    "literal-secret",
                    *(f"secret-field:{path}" for path in _blocked_pointers(candidate["payload"])),
                ],
            )
        elif key in seen:
            classification, action, reasons = "duplicate", "reuse", ["content-identical"]
        else:
            classification = (
                "local-package" if candidate["provenance"] == "local-only" else "importable"
            )
            action, reasons = "snapshot", ["native-local-resource"]
        seen.add(key)
        item = {
            "id": _digest({"candidate": candidate["id"], "action": action})[:32],
            "candidate_ids": [candidate["id"]],
            "kind": candidate["kind"],
            "name": candidate["name"],
            "classification": classification,
            "proposed_action": action,
            "current_targets": candidate["source_target"],
            "proposed_targets": candidate["source_target"],
            "proposed_destination": f"imported:{candidate['kind']}:{candidate['name']}",
            "reason_codes": reasons,
            "resolution": dict(
                (resolutions or {}).get(
                    item_id := _digest({"candidate": candidate["id"], "action": action})[:32],
                    _EMPTY_RESOLUTION,
                )
            ),
        }
        item["id"] = item_id
        if classification in {"secret-blocked", "conflict", "unsupported"} or (
            classification == "needs-choice"
            and any(reason in {"legacy-unscoped-targets", "excluded-changed"} for reason in reasons)
        ):
            blockers.append({"item_id": item["id"], "reason_codes": reasons})
        items.append(item)
    inventory = _digest(
        {
            "candidate_set_id": candidate_data["candidate_set_id"],
            "items": [{**item, "resolution": _EMPTY_RESOLUTION} for item in items],
            "apm_state": _apm_state_fingerprint(candidate_data),
        }
    )
    counts: dict[str, int] = {}
    for item in items:
        counts[item["classification"]] = counts.get(item["classification"], 0) + 1
    plan = {
        "schema_version": SCHEMA_VERSION,
        "coordinator": candidate_data["coordinator"],
        "scope": candidate_data.get("scope", "global"),
        "sources": candidate_data["sources"],
        "candidate_set_id": candidate_data["candidate_set_id"],
        "inventory_fingerprint": inventory,
        "items": items,
        "summary": counts,
        "warnings": [],
        "blockers": blockers,
    }
    if project_root is not None:
        plan["project_root"] = str(project_root)
    return _bind_plan_identity(plan)


def _contains_blocked(value: Any) -> bool:
    if isinstance(value, dict):
        return value.get("blocked") == "literal-secret" or any(
            _contains_blocked(v) for v in value.values()
        )
    if isinstance(value, list):
        return any(_contains_blocked(v) for v in value)
    return False


def _blocked_pointers(value: Any, prefix: str = "") -> list[str]:
    if isinstance(value, dict):
        if value == {"blocked": "literal-secret"}:
            return [prefix or "/"]
        return [
            pointer
            for key, child in value.items()
            for pointer in _blocked_pointers(
                child, f"{prefix}/{str(key).replace('~', '~0').replace('/', '~1')}"
            )
        ]
    if isinstance(value, list):
        return [
            pointer
            for index, child in enumerate(value)
            for pointer in _blocked_pointers(child, f"{prefix}/{index}")
        ]
    return []


def _resolution_identity(items: list[dict[str, Any]]) -> str:
    entries = sorted(
        ({"item_id": item["id"], "resolution": item["resolution"]} for item in items),
        key=lambda entry: entry["item_id"],
    )
    return _digest(entries)


def _bind_plan_identity(plan: dict[str, Any]) -> dict[str, Any]:
    immutable = {
        **plan,
        "items": [{**item, "resolution": _EMPTY_RESOLUTION} for item in plan["items"]],
    }
    plan_id = _digest(immutable)
    resolution_id = _resolution_identity(plan["items"])
    operation_id = _digest(
        {
            "candidate_set_id": plan["candidate_set_id"],
            "plan_id": plan_id,
            "resolution_id": resolution_id,
        }
    )[:32]
    return {
        **plan,
        "plan_id": plan_id,
        "resolution_id": resolution_id,
        "operation_id": operation_id,
    }


def _effective_targets(item: dict[str, Any]) -> list[str]:
    proposed = set(item["proposed_targets"])
    approved = item["resolution"].get("approved_targets", [])
    if approved:
        effective = set(approved)
        if not effective or not effective.issubset(proposed):
            raise ImportProtocolError(f"approved targets broaden item {item['id']}")
    else:
        effective = proposed
    if "legacy-unscoped-targets" in item["reason_codes"] and not approved:
        raise ImportProtocolError(
            f"reviewed plan still contains blockers: item requires explicit approved targets: {item['id']}"
        )
    return sorted(effective)


def _validate_resolution_preflight(plan: dict[str, Any]) -> None:
    for item in plan.get("items", []):
        if (
            item.get("classification") == "unsupported"
            and item.get("resolution", {}).get("decision") != "exclude"
        ):
            raise ImportProtocolError(
                "unsupported native client requires explicit leave-unmanaged decision: "
                f"{item['id']}"
            )


def _apply_env_bindings(payload: Any, bindings: dict[str, str]) -> Any:
    resolved = json.loads(json.dumps(payload))
    for pointer, variable in sorted(bindings.items()):
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", variable):
            raise ImportProtocolError(f"invalid environment binding variable: {variable}")
        if not pointer.startswith("/"):
            raise ImportProtocolError(f"environment binding must be a JSON pointer: {pointer}")
        parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]
        current = resolved
        for part in parts[:-1]:
            if not isinstance(current, dict) or part not in current:
                raise ImportProtocolError(f"environment binding path does not exist: {pointer}")
            current = current[part]
        leaf = parts[-1]
        if not isinstance(current, dict) or current.get(leaf) != {"blocked": "literal-secret"}:
            raise ImportProtocolError(
                f"environment binding does not target a blocked secret: {pointer}"
            )
        current[leaf] = f"${{{variable}}}"
    if _contains_blocked(resolved):
        raise ImportProtocolError("not every literal secret has an environment binding")
    return resolved


def _canonicalize_mcp_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Translate legacy-only secret containers after reviewed resolution."""
    result = dict(payload)
    env_literal = result.pop("env_literal", None)
    if env_literal is not None:
        if not isinstance(env_literal, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in env_literal.items()
        ):
            raise ImportProtocolError("resolved MCP env_literal must be a string map")
        result["env"] = {**result.get("env", {}), **env_literal}
    headers_literal = result.pop("headers_literal", None)
    if headers_literal is not None:
        if not isinstance(headers_literal, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in headers_literal.items()
        ):
            raise ImportProtocolError("resolved MCP headers_literal must be a string map")
        result["headers"] = {**result.get("headers", {}), **headers_literal}
    authorization = result.pop("authorization", result.pop("auth", None))
    if authorization is not None:
        if not isinstance(authorization, str):
            raise ImportProtocolError("resolved MCP authorization must be a string")
        result["headers"] = {
            **result.get("headers", {}),
            "Authorization": authorization,
        }
    return result


def _validate_plan(data: Any, candidates: dict[str, Any]) -> dict[str, Any]:
    required = {
        "schema_version",
        "coordinator",
        "operation_id",
        "plan_id",
        "resolution_id",
        "sources",
        "candidate_set_id",
        "inventory_fingerprint",
        "items",
        "summary",
        "warnings",
        "blockers",
    }
    optional = {"scope", "project_root"}
    if not isinstance(data, dict) or not required.issubset(data) or set(data) - required - optional:
        raise ImportProtocolError("plan schema fields mismatch")
    if data["schema_version"] != SCHEMA_VERSION or data["coordinator"] != candidates["coordinator"]:
        raise ImportProtocolError("plan coordinator/schema mismatch")
    if data["candidate_set_id"] != candidates["candidate_set_id"]:
        raise ImportProtocolError("plan is bound to a different candidate set")
    plan_scope = _scope_identity(data)
    candidate_scope = _scope_identity(candidates)
    if plan_scope != candidate_scope:
        raise ImportProtocolError("plan and candidate project roots do not match; rescan")
    resolutions = {item["id"]: item.get("resolution", {}) for item in data["items"]}
    expected = _plan(candidates, resolutions)
    if "scope" not in data:
        expected.pop("scope", None)
        expected = _bind_plan_identity(
            {
                key: value
                for key, value in expected.items()
                if key not in {"plan_id", "resolution_id", "operation_id"}
            }
        )
    if _canonical(data) != _canonical(expected):
        raise ImportProtocolError("reviewed plan immutable fields or resolution identity changed")
    return data


def _validate_plan_identity(data: dict[str, Any]) -> None:
    _scope_identity(data)
    body = {
        key: value
        for key, value in data.items()
        if key not in {"plan_id", "resolution_id", "operation_id"}
    }
    immutable = {
        **body,
        "items": [{**item, "resolution": _EMPTY_RESOLUTION} for item in data["items"]],
    }
    plan_id = _digest(immutable)
    resolution_id = _resolution_identity(data["items"])
    operation_id = _digest(
        {
            "candidate_set_id": data["candidate_set_id"],
            "plan_id": plan_id,
            "resolution_id": resolution_id,
        }
    )[:32]
    if (plan_id, resolution_id, operation_id) != (
        data.get("plan_id"),
        data.get("resolution_id"),
        data.get("operation_id"),
    ):
        raise ImportProtocolError("reviewed plan identity is invalid")


def _validate_apply_scope(
    plan: dict[str, Any], project_root: Path | None
) -> tuple[str, Path | None]:
    scope, plan_root = _scope_identity(plan)
    requested_root = (
        _canonical_project_root(project_root)
        if project_root is not None
        else plan_root
        if scope == "project"
        else None
    )
    if (scope == "project" and requested_root != plan_root) or (
        scope == "global" and requested_root is not None
    ):
        raise ImportProtocolError("apply scope/project root mismatch; rescan")
    if plan_root is not None:
        for managed_path in (plan_root / "apm.yml", plan_root / "apm.lock.yaml"):
            if managed_path.is_symlink():
                raise ImportProtocolError(f"project APM state is a symlink: {managed_path}")
    return scope, plan_root


def _resolve_source(candidate: dict[str, Any], preimages: dict[str, dict[str, Any]]) -> Path | None:
    ids = candidate["source_preimage_ids"]
    if len(ids) != 1:
        return None
    return Path(preimages[ids[0]]["absolute_path"])


def _structured_dependency(
    candidate: dict[str, Any],
    targets: list[str],
    preimages: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Translate legacy remote package-like declarations without copying Omni JSON."""
    if candidate["provenance"] == "local-only" or candidate["kind"] not in {
        "package",
        "skill",
        "plugin",
    }:
        return None
    payload = candidate["payload"]
    source = payload.get("source")
    if not isinstance(source, str) or not source.strip():
        return None
    local_source: Path | None = None
    parsed = urlsplit(source)
    if parsed.scheme == "file":
        if parsed.netloc not in {"", "localhost"}:
            raise ImportProtocolError("file dependency URL must be local")
        local_source = Path(_file_url_path(parsed.path))
    else:
        from apm_cli.models.dependency.reference import DependencyReference

        if DependencyReference.is_local_path(source):
            local_source = Path(source).expanduser()
    if local_source is not None:
        if not local_source.is_absolute():
            source_ids = candidate.get("source_preimage_ids", [])
            if not preimages or len(source_ids) != 1:
                raise ImportProtocolError("relative legacy dependency has no source base")
            local_source = Path(preimages[source_ids[0]]["absolute_path"]).parent / local_source
        dependency: dict[str, Any] = {
            "path": str(local_source.resolve(strict=False)),
            "targets": targets,
        }
    else:
        dependency = {"git": source, "targets": targets}
    if isinstance(payload.get("ref"), str) and payload["ref"]:
        dependency["ref"] = payload["ref"]
    path = payload.get("skill_path") or payload.get("path")
    if local_source is None and isinstance(path, str) and path:
        dependency["path"] = path
    if isinstance(payload.get("skills"), list) and payload["skills"]:
        dependency["skills"] = payload["skills"]
    if candidate["kind"] == "skill":
        dependency["alias"] = candidate["name"]
    return dependency


def _file_url_path(raw_path: str, *, windows: bool | None = None) -> str:
    path = unquote(raw_path)
    if (os.name == "nt" if windows is None else windows) and re.match(r"^/[A-Za-z]:/", path):
        return path[1:]
    return path


def _copy_source(source: Path, destination: Path, approved: set[str]) -> None:
    if source.is_dir():
        for entry in _tree_entries(source):
            if entry["kind"] == "file" and entry["mode"] & 0o111 and entry["path"] not in approved:
                raise ImportProtocolError(f"executable requires approval: {entry['path']}")
        shutil.copytree(source, destination)
    else:
        executable = bool(stat.S_IMODE(source.stat().st_mode) & 0o111)
        if executable and not approved:
            raise ImportProtocolError(f"executable requires approval: {source.name}")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copy2(source, destination)


def _staged_fingerprint(candidate: dict[str, Any], staged_source: Path) -> str:
    if candidate["payload"].get("source") == "secured-path":
        return _preimage(staged_source)["content_fingerprint"]
    payload = _load_structured(staged_source)
    clean, _ = _sanitize(payload)
    return _digest(clean)


def _replace_hook_paths(value: Any, variants: set[str], replacement: str) -> Any:
    if isinstance(value, dict):
        return {
            key: _replace_hook_paths(child, variants, replacement) for key, child in value.items()
        }
    if isinstance(value, list):
        return [_replace_hook_paths(child, variants, replacement) for child in value]
    if isinstance(value, str):
        for variant in sorted(variants, key=len, reverse=True):
            if variant:
                value = value.replace(variant, replacement)
    return value


def _snapshot(
    candidate: dict[str, Any],
    item: dict[str, Any],
    source: Path,
    expected_source: dict[str, Any],
    operation_id: str,
    preimages: dict[str, dict[str, Any]] | None = None,
) -> Path:
    slug = re.sub(r"[^a-z0-9._-]+", "-", candidate["name"].lower()).strip("-") or "imported"
    target_key = "-".join(sorted(candidate["source_target"]))
    final = (
        Path.home()
        / ".apm"
        / "imported"
        / candidate["kind"]
        / f"{slug}-{target_key}-{candidate['content_fingerprint'][:12]}"
    )
    if final.exists():
        metadata = final / ".apm-import.json"
        if metadata.is_file() and candidate["id"] in json.loads(
            metadata.read_text(encoding="utf-8")
        ).get("candidate_ids", []):
            return final
        raise ImportProtocolError(f"snapshot destination collision: {final}")
    root = SecureRoot(final.parent).ensure()
    stage_name = f".{final.name}-{os.urandom(12).hex()}"
    stage = root.make_directory(stage_name)
    try:
        kind = candidate["kind"]
        layout = candidate["payload"].get("import_layout")
        approved = set(item["resolution"].get("approved_executables", []))
        metadata_extra: dict[str, Any] = {}
        if layout == "compiled-instruction":
            target = candidate["payload"]["target"]
            if candidate["source_target"] != [target]:
                raise ImportProtocolError("compiled instruction target mismatch")
            relative = Path(candidate["payload"]["relative_path"])
            if relative.is_absolute() or ".." in relative.parts:
                raise ImportProtocolError("compiled instruction path escapes target root")
            destination = stage / ".apm" / "native" / "instructions" / target / relative
            _copy_source(source, destination, approved)
            metadata_extra = {
                "layout": layout,
                "target": target,
                "format_id": candidate["payload"]["format_id"],
                "relative_path": relative.as_posix(),
            }
        elif layout == "workflow":
            row = candidate["payload"].get("workflow")
            if not isinstance(row, dict) or not isinstance(row.get("prompt"), str):
                raise ImportProtocolError("workflow candidate payload is malformed")
            frontmatter = {
                key: row[key]
                for key in (
                    "name",
                    "interval",
                    "schedule_hour",
                    "schedule_day",
                    "mode",
                    "model",
                    "reasoning_effort",
                )
                if row.get(key) is not None
            }
            destination = stage / ".apm" / "prompts" / f"{slug}.prompt.md"
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            atomic_write_text(
                destination,
                f"---\n{yaml_to_str(frontmatter, sort_keys=False).rstrip()}\n---\n{row['prompt']}",
                new_file_mode=0o600,
            )
            metadata_extra = {"layout": layout, "workflow": row}
        elif layout == "hook-bundle":
            if preimages is None:
                raise ImportProtocolError("hook snapshot preimages are missing")
            descriptor = candidate["payload"].get("descriptor")
            scripts = candidate["payload"].get("scripts")
            if not isinstance(descriptor, dict) or not isinstance(scripts, list):
                raise ImportProtocolError("hook bundle payload is malformed")
            rewritten = json.loads(json.dumps(descriptor))
            destination = stage / ".apm" / "hooks" / f"{slug}.json"
            for script in scripts:
                if not isinstance(script, dict) or script.get("preimage_id") not in preimages:
                    raise ImportProtocolError("hook script preimage is missing")
                expected = preimages[script["preimage_id"]]
                script_source = Path(expected["absolute_path"])
                relative = Path(str(script.get("relative_path", "")))
                if relative.is_absolute() or ".." in relative.parts:
                    raise ImportProtocolError("hook script path escapes native root")
                staged_relative = Path("resources") / relative
                replacement = f"./{staged_relative.as_posix()}"
                variants = {str(script_source), relative.as_posix()}
                with contextlib.suppress(ValueError):
                    variants.add(script_source.relative_to(source.parent).as_posix())
                rewritten = _replace_hook_paths(rewritten, variants, replacement)
                _copy_source(script_source, destination.parent / staged_relative, approved)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            atomic_write_text(
                destination,
                json.dumps(rewritten, indent=2, sort_keys=True) + "\n",
                new_file_mode=0o600,
            )
            metadata_extra = {"layout": layout}
        elif layout == "canvas":
            destination = stage / ".apm" / "extensions" / slug
            _copy_source(source, destination, approved)
            metadata_extra = {"layout": layout}
        elif kind == "plugin":
            for entry in _tree_entries(source):
                if (
                    entry["kind"] == "file"
                    and entry["mode"] & 0o111
                    and entry["path"] not in approved
                ):
                    raise ImportProtocolError(f"executable requires approval: {entry['path']}")
            shutil.copytree(source, stage, dirs_exist_ok=True)
            if _staged_fingerprint(candidate, stage) != candidate["content_fingerprint"]:
                raise ImportProtocolError("staged snapshot differs from reviewed candidate")
            from apm_cli.deps.plugin_parser import normalize_plugin_directory

            plugin_json = stage / ".claude-plugin" / "plugin.json"
            if not plugin_json.is_file():
                plugin_json = stage / ".codex-plugin" / "plugin.json"
            normalize_plugin_directory(stage, plugin_json if plugin_json.is_file() else None)
            destination = None
        elif kind == "instruction":
            destination = stage / ".apm" / "instructions" / f"{slug}.instructions.md"
        elif kind == "agent":
            destination = stage / ".apm" / "agents" / f"{slug}.agent.md"
        elif kind == "command":
            destination = stage / ".apm" / "commands" / f"{slug}.command.md"
        elif kind == "skill":
            destination = stage / ".apm" / "skills" / slug
        elif kind == "hook":
            destination = stage / ".apm" / "hooks" / f"{slug}{source.suffix or '.json'}"
        elif kind == "mcp":
            destination = None
        else:
            raise ImportProtocolError(f"unsupported snapshot kind: {kind}")
        manifest: dict[str, Any] = {"name": f"imported-{slug}", "version": "1.0.0"}
        if kind == "plugin" or layout in {
            "compiled-instruction",
            "workflow",
            "hook-bundle",
            "canvas",
        }:
            pass
        elif destination is not None:
            _copy_source(source, destination, approved)
            if _staged_fingerprint(candidate, destination) != candidate["content_fingerprint"]:
                raise ImportProtocolError("staged snapshot differs from reviewed candidate")
        else:
            manifest["dependencies"] = {
                "mcp": [{"name": candidate["name"], "registry": False, **candidate["payload"]}]
            }
        current_source = _preimage(source)
        if any(
            current_source[field] != expected_source[field]
            for field in ("id", "kind", "size", "mode", "content_fingerprint")
        ):
            raise ImportProtocolError(f"source changed while snapshotting: {source}")
        (stage / ".apm").mkdir(mode=0o700, exist_ok=True)
        atomic_write_text(
            stage / "apm.yml", yaml_to_str(manifest, sort_keys=False), new_file_mode=0o600
        )
        metadata = {
            "schema_version": SCHEMA_VERSION,
            "candidate_ids": [candidate["id"]],
            "root_id": candidate["root_id"],
            "content_fingerprint": candidate["content_fingerprint"],
            "targets": candidate["source_target"],
            "kind": kind,
            "operation_id": operation_id,
            **metadata_extra,
        }
        atomic_write_text(
            stage / ".apm-import.json",
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            new_file_mode=0o600,
        )
        for staged_path in [stage, *stage.rglob("*")]:
            harden_path(
                staged_path,
                executable=staged_path.is_file()
                and bool(stat.S_IMODE(staged_path.stat().st_mode) & 0o111),
            )
        return root.publish_directory(stage.name, final.name)
    except Exception:
        with contextlib.suppress(OSError, ValueError):
            root.remove_directory(stage.name)
        raise


def _record_ownership(candidate: dict[str, Any], targets: list[str], operation_id: str) -> Path:
    slug = re.sub(r"[^a-z0-9._-]+", "-", candidate["name"].lower()).strip("-") or "imported"
    target_key = "-".join(sorted(targets))
    path = (
        Path.home()
        / ".apm"
        / "imported"
        / candidate["kind"]
        / f"{slug}-{target_key}-{candidate['content_fingerprint'][:12]}"
    )
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "candidate_ids": [candidate["id"]],
        "root_id": candidate["root_id"],
        "content_fingerprint": candidate["content_fingerprint"],
        "targets": targets,
        "kind": candidate["kind"],
        "operation_id": operation_id,
    }
    existing = path / ".apm-import.json"
    if path.exists():
        root = SecureRoot(path)
        root.verify()
        if not existing.is_file():
            raise ImportProtocolError(f"import ownership collision: {path}")
        current = json.loads(existing.read_text(encoding="utf-8"))
        if current != metadata:
            raise ImportProtocolError(f"import ownership collision: {path}")
        return path
    root = SecureRoot(path).ensure()
    root.write_text(".apm-import.json", json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return path


def _update_manifest(
    dependencies: list[Any],
    mcp_dependencies: list[dict[str, Any]],
    *,
    path: Path | None = None,
) -> Path:
    path = path or Path.home() / ".apm" / "apm.yml"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = (
        load_yaml(path)
        if path.is_file()
        else {
            "name": "global" if path.parent.name == ".apm" else path.parent.name,
            "version": "1.0.0",
        }
    )
    if not isinstance(data, dict):
        raise ImportProtocolError("global APM manifest is not an object")
    dep_root = data.setdefault("dependencies", {})
    current = dep_root.setdefault("apm", [])
    for dependency in dependencies:
        if dependency not in current:
            current.append(dependency)
    current_mcp = dep_root.setdefault("mcp", [])
    for dependency in mcp_dependencies:
        if dependency not in current_mcp:
            current_mcp.append(dependency)
    dump_yaml_roundtrip(data, path)
    harden_path(path)
    return path


def _register_marketplace(name: str, payload: dict[str, Any]) -> None:
    from apm_cli.marketplace.models import MarketplaceSource

    source = payload.get("source", payload)
    if not isinstance(source, dict) or not isinstance(source.get("url"), str):
        raise ImportProtocolError(f"marketplace {name} has no canonical URL")
    normalized = MarketplaceSource(
        name=name,
        url=source["url"],
        ref=str(source.get("ref") or "main"),
        path=str(source.get("path") or "marketplace.json"),
    ).to_dict()
    if isinstance(source.get("install_path"), str):
        normalized["install_path"] = source["install_path"]
    path = Path.home() / ".apm" / "marketplaces.json"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {"marketplaces": []}
    entries = data.setdefault("marketplaces", [])
    matching = [item for item in entries if item.get("name") == name]
    if matching and matching != [normalized]:
        raise ImportProtocolError(f"marketplace name collision: {name}")
    if not matching:
        entries.append(normalized)
    _write_json(path.resolve(), data)


def _contains_text(value: Any, needle: str) -> bool:
    if isinstance(value, dict):
        return any(_contains_text(child, needle) for child in value.values())
    if isinstance(value, list):
        return any(_contains_text(child, needle) for child in value)
    return isinstance(value, str) and Path(value).expanduser().resolve(strict=False) == Path(
        needle
    ).resolve(strict=False)


def _remove_activation(value: Any, needle: str) -> Any:
    if isinstance(value, dict):
        return {
            key: _remove_activation(child, needle)
            for key, child in value.items()
            if not _contains_text(child, needle)
        }
    if isinstance(value, list):
        return [
            _remove_activation(child, needle)
            for child in value
            if not _contains_text(child, needle)
        ]
    return value


def _capture_plugin_activation(
    candidate: dict[str, Any], source: Path, journal: dict[str, Any]
) -> None:
    for raw_path in candidate["payload"].get("activation_paths", []):
        config = Path(raw_path)
        state = capture_activation(config)
        data = json.loads(state.data)
        if not _contains_text(data, str(source)):
            continue
        if any(
            record["path"] == str(state.path) and record["source"] == str(source)
            for record in journal.get("retired_activations", [])
        ):
            continue
        backup_name = f"activation-{_digest((str(state.path), str(source)))[:16]}.base64"
        backup = journal_root(journal["operation_id"], create=True).write_text(
            backup_name, base64.b64encode(state.data).decode("ascii") + "\n"
        )
        journal.setdefault("retired_activations", []).append(
            {
                "path": str(state.path),
                "backup": str(backup),
                "source": str(source),
                "mode": state.mode,
                "hash": hashlib.sha256(state.data).hexdigest(),
            }
        )


def _retire_plugin_activation(
    candidate: dict[str, Any], source: Path, journal: dict[str, Any]
) -> None:
    for raw_path in candidate["payload"].get("activation_paths", []):
        config = Path(raw_path)
        if not config.is_file() or config.is_symlink():
            raise ImportProtocolError(f"plugin activation disappeared: {config}")
        data = json.loads(config.read_text(encoding="utf-8"))
        if not _contains_text(data, str(source)):
            continue
        updated = dict(data)
        plugins = updated.get("plugins")
        if isinstance(plugins, dict):
            updated_plugins = dict(plugins)
            for key, installs in plugins.items():
                if isinstance(installs, list):
                    kept = [entry for entry in installs if not _contains_text(entry, str(source))]
                    if kept:
                        updated_plugins[key] = kept
                    else:
                        updated_plugins.pop(key, None)
                elif _contains_text(installs, str(source)):
                    updated_plugins.pop(key, None)
            updated["plugins"] = updated_plugins
        else:
            updated = _remove_activation(data, str(source))
        _write_json(config.resolve(), updated)
        if _contains_text(updated, str(source)):
            raise ImportProtocolError(f"failed to retire plugin activation: {source}")


def _install_manifest(path: Path, targets: list[str], *, user_scope: bool = True) -> Any:
    """Run the existing install application service while the import lock is held."""
    from apm_cli.constants import InstallMode
    from apm_cli.core.command_logger import InstallLogger
    from apm_cli.core.scope import InstallScope
    from apm_cli.deps.lockfile import LockFile, get_lockfile_path
    from apm_cli.install.request import InstallRequest
    from apm_cli.install.service import InstallService
    from apm_cli.install.service_integration import run_service_integrations
    from apm_cli.models.apm_package import APMPackage
    from apm_cli.models.results import InstallDisposition

    package = APMPackage.from_apm_yml(path)
    logger = InstallLogger(verbose=False)
    lock_path = get_lockfile_path(path.parent)
    existing_lock = LockFile.read(lock_path)
    old_mcp_servers = set(existing_lock.mcp_servers) if existing_lock else set()
    old_mcp_configs = dict(existing_lock.mcp_configs) if existing_lock else {}
    old_mcp_provenance = dict(existing_lock.mcp_config_provenance) if existing_lock else {}
    old_mcp_target_servers = dict(existing_lock.mcp_target_servers) if existing_lock else {}
    old_mcp_target_servers_present = (
        existing_lock._mcp_target_servers_present if existing_lock else True
    )
    with (
        contextlib.chdir(path.parent),
        contextlib.redirect_stdout(io.StringIO()),
        contextlib.redirect_stderr(io.StringIO()),
    ):
        result = InstallService().run(
            InstallRequest(
                apm_package=package,
                logger=logger,
                scope=InstallScope.USER if user_scope else InstallScope.PROJECT,
                target=sorted(set(targets)),
            )
        )
        run_service_integrations(
            SimpleNamespace(
                project_root=path.parent,
                scope=InstallScope.USER if user_scope else InstallScope.PROJECT,
                install_mode=InstallMode.ALL,
                logger=logger,
                runtime=None,
                exclude=None,
                trust_transitive_mcp=True,
                no_policy=False,
                verbose=False,
            ),
            apm_package=package,
            mcp_deps=package.get_all_mcp_dependencies(),
            lock_path=lock_path,
            existing_lock=existing_lock,
            old_mcp_servers=old_mcp_servers,
            old_mcp_configs=old_mcp_configs,
            old_mcp_provenance=old_mcp_provenance,
            old_mcp_target_servers=old_mcp_target_servers,
            old_mcp_target_servers_present=old_mcp_target_servers_present,
            diagnostics=result.diagnostics,
            explicit_target=targets,
            target_decision=result.target_decision,
        )
    if result.disposition is not InstallDisposition.SUCCESS:
        raise ImportProtocolError(f"APM install did not complete: {result.disposition.value}")
    return result


def _install_import_manifest(path: Path, targets: list[str], scope: str) -> Any | None:
    if not targets:
        return None
    if scope == "global":
        return _install_manifest(path, targets)
    return _install_manifest(path, targets, user_scope=False)


def _verify_deployment(
    manifest_path: Path, journal: dict[str, Any], *, require_lock: bool = True
) -> None:
    from apm_cli.models.apm_package import APMPackage

    package = APMPackage.from_apm_yml(manifest_path)
    if (
        require_lock
        and (package.get_apm_dependencies() or package.get_all_mcp_dependencies())
        and not (manifest_path.parent / "apm.lock.yaml").is_file()
    ):
        raise ImportProtocolError("APM install produced no lockfile ownership record")
    for raw in journal.get("created_paths", []):
        path = Path(raw)
        metadata = path / ".apm-import.json"
        if not path.is_dir() or path.is_symlink() or not metadata.is_file():
            raise ImportProtocolError(f"imported package ownership missing: {path}")
        payload = json.loads(metadata.read_text(encoding="utf-8"))
        if payload.get("operation_id") != journal["operation_id"]:
            raise ImportProtocolError(f"imported package ownership mismatch: {path}")


def _verify_post_retirement(journal: dict[str, Any]) -> None:
    for record in journal.get("retired_activations", []):
        path = Path(record["path"])
        if not path.is_file() or path.is_symlink():
            raise ImportProtocolError(f"retired activation config missing: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        if _contains_text(data, record["source"]):
            raise ImportProtocolError(f"native activation remains active: {record['source']}")


def _restore_retired_activations(journal: dict[str, Any]) -> None:
    for record in journal.get("retired_activations", []):
        path = Path(record["path"])
        expected = base64.b64decode(
            Path(record["backup"]).read_text(encoding="utf-8").strip(),
            validate=True,
        )
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        restore_file_bytes(path, expected, record["mode"])
        restored_mode = stat.S_IMODE(path.stat().st_mode)
        if (
            path.read_bytes() != expected
            or hashlib.sha256(expected).hexdigest() != record["hash"]
            or (os.name != "nt" and restored_mode != record["mode"])
        ):
            raise ImportProtocolError(f"activation backup restore verification failed: {path}")
    journal["retired_activations"] = []
    journal["phase"] = "ownership-verified"
    write_journal(journal)


def _audit_import(manifest_path: Path) -> None:
    from apm_cli.policy.ci_checks import run_baseline_checks

    with contextlib.chdir(manifest_path.parent):
        result = run_baseline_checks(manifest_path.parent, fail_fast=False, ci_mode=True)
    if not result.passed:
        failures = "; ".join(
            f"{check.name}: {check.message}"
            + (f" ({'; '.join(check.details)})" if check.details else "")
            for check in result.failed_checks
        )
        raise ImportProtocolError(f"APM audit baseline failed after import: {failures}")


class ImportService:
    """Scan, apply, and recover one strict import operation."""

    def scan(
        self,
        *,
        sources: tuple[str, ...],
        candidate_file: Path | None,
        plan_json: Path | None,
        coordinator: str,
        project_root: Path | None = None,
    ) -> dict[str, Any]:
        if coordinator not in COORDINATORS:
            raise ImportProtocolError(f"unsupported coordinator: {coordinator}")
        scope = "project" if project_root is not None else "global"
        canonical_root = _canonical_project_root(project_root) if project_root is not None else None
        if candidate_file and candidate_file.is_file():
            _validate_protocol_file(candidate_file)
            data = _validate_candidate_envelope(
                json.loads(candidate_file.read_text(encoding="utf-8"))
            )
            if data["coordinator"] != coordinator:
                raise ImportProtocolError("candidate coordinator mismatch")
            existing_scope, existing_root = _scope_identity(data)
            if existing_scope != scope or existing_root != canonical_root:
                raise ImportProtocolError("candidate scope/project root mismatch; rescan")
            if sources:
                candidates_by_id = {item["id"]: item for item in data["candidates"]}
                preimages_by_id = {item["id"]: item for item in data["source_preimages"]}
                discovered, preimages = _discover_targets(
                    sorted(set(sources)), project_root=canonical_root
                )
                candidates_by_id.update((item["id"], item) for item in discovered)
                preimages_by_id.update((item["id"], item) for item in preimages)
                if scope == "global":
                    unmanaged, unmanaged_preimages = _discover_unmanaged_clients(list(sources))
                    candidates_by_id.update((item["id"], item) for item in unmanaged)
                    preimages_by_id.update((item["id"], item) for item in unmanaged_preimages)
                data["sources"] = sorted(set(data["sources"]) | set(sources))
                data["source_preimages"] = sorted(
                    preimages_by_id.values(), key=lambda value: value["id"]
                )
                data["candidates"] = sorted(
                    candidates_by_id.values(), key=lambda value: value["id"]
                )
                data["candidate_set_id"] = _candidate_set_identity(data)
                _write_json(candidate_file, data)
        else:
            all_candidates: list[dict[str, Any]] = []
            all_preimages: list[dict[str, Any]] = []
            normalized_sources = sorted(set(sources))
            candidates, preimages = _discover_targets(
                normalized_sources, project_root=canonical_root
            )
            all_candidates.extend(candidates)
            all_preimages.extend(preimages)
            if scope == "global":
                unmanaged, unmanaged_preimages = _discover_unmanaged_clients(normalized_sources)
                all_candidates.extend(unmanaged)
                all_preimages.extend(unmanaged_preimages)
            preimages_by_id = {item["id"]: item for item in all_preimages}
            data = {
                "schema_version": SCHEMA_VERSION,
                "coordinator": coordinator,
                "scope": scope,
                "sources": normalized_sources,
                "candidate_set_id": "",
                "source_preimages": sorted(preimages_by_id.values(), key=lambda value: value["id"]),
                "candidates": sorted(all_candidates, key=lambda value: value["id"]),
            }
            if canonical_root is not None:
                data["project_root"] = str(canonical_root)
            data["candidate_set_id"] = _candidate_set_identity(data)
            if candidate_file:
                _write_json(candidate_file, data)
        plan = _plan(data)
        if plan_json:
            _write_json(plan_json, plan)
        return plan

    def apply(self, **kwargs: Any) -> dict[str, Any]:
        plan_file = Path(kwargs["plan_file"])
        raw_plan = json.loads(plan_file.read_text(encoding="utf-8"))
        _validate_plan_identity(raw_plan)
        for item in raw_plan.get("items", []):
            _effective_targets(item)
        _validate_resolution_preflight(raw_plan)
        operation = str(raw_plan.get("operation_id", ""))
        with allow_operation(operation), lifecycle_operation():
            return self._apply_locked(**kwargs)

    def _apply_locked(
        self,
        *,
        candidate_file: Path,
        plan_file: Path,
        coordinator: str,
        omni_preimage_set: str | None,
        token: bytes | None,
        project_root: Path | None = None,
    ) -> dict[str, Any]:
        _validate_protocol_file(candidate_file)
        _validate_protocol_file(plan_file)
        if candidate_file.parent.resolve() != plan_file.parent.resolve():
            raise ImportProtocolError(
                "candidate and plan files must share one secured operation root"
            )
        candidates = _validate_candidate_envelope(
            json.loads(candidate_file.read_text(encoding="utf-8"))
        )
        plan_data = json.loads(plan_file.read_text(encoding="utf-8"))
        _validate_plan_identity(plan_data)
        scope, plan_root = _validate_apply_scope(plan_data, project_root)
        operation = plan_data["operation_id"]
        existing = read_journal(operation)
        plan = plan_data if existing else _validate_plan(plan_data, candidates)
        if coordinator != plan["coordinator"]:
            raise ImportProtocolError("apply coordinator mismatch")
        if coordinator == "omni-v24" and (
            not omni_preimage_set or token is None or len(token) < 32
        ):
            raise ImportProtocolError(
                "omni-v24 apply requires preimage set and 256-bit token on stdin"
            )
        if coordinator == "standalone" and (omni_preimage_set or token):
            raise ImportProtocolError("standalone apply rejects external commit fields")
        _validate_resolution_preflight(plan)
        _validate_preimages(candidates)
        if existing:
            expected_binding = {
                "coordinator": coordinator,
                "candidate_set_id": candidates["candidate_set_id"],
                "inventory_fingerprint": plan["inventory_fingerprint"],
                "plan_id": plan["plan_id"],
                "resolution_id": plan["resolution_id"],
                "omni_preimage_set": omni_preimage_set,
            }
            if any(existing.get(key) != value for key, value in expected_binding.items()):
                raise ImportProtocolError("journal binding does not match reviewed resolution")
            if scope == "project" and (
                existing.get("scope") != "project" or existing.get("project_root") != str(plan_root)
            ):
                raise ImportProtocolError("journal project root does not match reviewed plan")
        if existing and existing.get("state") in {"complete", "awaiting-external-commit"}:
            if (
                token
                and existing.get("token_hash")
                and not hmac.compare_digest(
                    existing["token_hash"], hashlib.sha256(token).hexdigest()
                )
            ):
                raise ImportProtocolError("operation capability mismatch")
            return self.status(operation)
        journal = existing or {
            "schema_version": SCHEMA_VERSION,
            "operation_id": operation,
            "coordinator": coordinator,
            "scope": scope,
            "project_root": str(plan_root) if plan_root is not None else None,
            "state": "recoverable-partial",
            "phase": "planned",
            "candidate_set_id": candidates["candidate_set_id"],
            "inventory_fingerprint": plan["inventory_fingerprint"],
            "plan_id": plan["plan_id"],
            "resolution_id": plan["resolution_id"],
            "omni_preimage_set": omni_preimage_set,
            "token_hash": hashlib.sha256(token).hexdigest() if token else None,
            "created_paths": [],
            "manifest_path": str(
                plan_root / "apm.yml" if plan_root is not None else Path.home() / ".apm" / "apm.yml"
            ),
            "cleaned": False,
        }
        with allow_operation(operation), lifecycle_operation():
            try:
                write_journal(journal)
                if "backups" not in journal:
                    journal["backups"] = []
                    managed_paths = (
                        (
                            Path(journal["manifest_path"]),
                            plan_root / "apm.lock.yaml",
                        )
                        if plan_root is not None
                        else (
                            Path(journal["manifest_path"]),
                            Path.home() / ".apm" / "marketplaces.json",
                            Path.home() / ".apm" / "import-exclusions.yml",
                        )
                    )
                    for index, managed_path in enumerate(managed_paths):
                        record = {
                            "path": str(managed_path),
                            "existed": managed_path.is_file(),
                            "backup": None,
                            "mode": None,
                            "encoding": "base64",
                        }
                        if managed_path.is_file():
                            raw = managed_path.read_bytes()
                            backup = journal_root(operation, create=True).write_text(
                                f"managed-{index}.base64",
                                base64.b64encode(raw).decode("ascii") + "\n",
                            )
                            record["backup"] = str(backup)
                            record["mode"] = stat.S_IMODE(managed_path.stat().st_mode)
                        journal["backups"].append(record)
                journal["phase"] = "backed-up"
                write_journal(journal)
                by_id = {item["id"]: item for item in candidates["candidates"]}
                preimages = {item["id"]: item for item in candidates["source_preimages"]}
                dependencies: list[Any] = []
                mcp_dependencies: list[dict[str, Any]] = []
                exclusions = _load_exclusions() if scope == "global" else {}
                imported_plugins: list[tuple[dict[str, Any], Path]] = []
                effective_install_targets: set[str] = set()
                for item in plan["items"]:
                    explicit_decision = item["resolution"].get("decision")
                    decision = explicit_decision or (
                        "exclude"
                        if item["classification"] == "excluded"
                        else "import"
                        if item["classification"] in {"importable", "local-package"}
                        else "reuse"
                    )
                    candidate_ids = item["candidate_ids"]
                    candidate = by_id[candidate_ids[0]]
                    resolved_conflict = False
                    if item["classification"] == "conflict":
                        selected = item["resolution"].get("selected_origin_id")
                        if decision != "select-origin" or selected not in candidate_ids:
                            raise ImportProtocolError(
                                f"conflict requires a valid selected_origin_id: {item['id']}"
                            )
                        candidate = by_id[selected]
                        resolved_conflict = True
                        for loser_id in candidate_ids:
                            if loser_id != selected:
                                loser = by_id[loser_id]
                                exclusions[loser_id] = _exclusion_entry(
                                    loser, loser["source_target"]
                                )
                        decision = "import"
                    target_item = {
                        **item,
                        "current_targets": candidate["source_target"],
                        "proposed_targets": candidate["source_target"],
                    }
                    effective_targets = _effective_targets(target_item)
                    if item["classification"] == "needs-choice" and not item["resolution"].get(
                        "decision"
                    ):
                        raise ImportProtocolError(
                            f"item requires an explicit executable resolution: {item['id']}"
                        )
                    if "excluded-changed" in item["reason_codes"]:
                        raise ImportProtocolError(
                            "changed exclusion must be removed explicitly before import: "
                            f"{candidate['id']}"
                        )
                    if decision == "exclude":
                        exclusions[candidate["id"]] = _exclusion_entry(candidate, effective_targets)
                        continue
                    if decision in {"reuse", "retain"}:
                        continue
                    if item["classification"] == "secret-blocked":
                        if decision != "map-secret" or not item["resolution"].get("env_bindings"):
                            raise ImportProtocolError(
                                f"secret-blocked item requires map-secret: {item['id']}"
                            )
                        candidate = {
                            **candidate,
                            "payload": _apply_env_bindings(
                                candidate["payload"], item["resolution"]["env_bindings"]
                            ),
                            "secret_blocked": False,
                        }
                        if candidate["kind"] == "mcp":
                            candidate = {
                                **candidate,
                                "payload": _canonicalize_mcp_payload(candidate["payload"]),
                            }
                        decision = "import"
                    if decision != "import":
                        raise ImportProtocolError(f"unsupported resolution decision: {decision}")
                    if item["classification"] == "unsupported" or (
                        item["classification"] == "conflict" and not resolved_conflict
                    ):
                        raise ImportProtocolError(f"item is not importable: {item['id']}")
                    effective_install_targets.update(effective_targets)
                    if candidate["kind"] == "marketplace":
                        _register_marketplace(candidate["name"], candidate["payload"])
                        ownership = _record_ownership(candidate, effective_targets, operation)
                        journal["created_paths"].append(str(ownership))
                        continue
                    if candidate["kind"] == "plugin" and candidate["provenance"] == "marketplace":
                        dependency = {
                            "name": candidate["payload"]["plugin"],
                            "marketplace": candidate["payload"]["marketplace"],
                            "targets": effective_targets,
                        }
                        for key in ("version", "ref"):
                            if isinstance(candidate["payload"].get(key), str):
                                dependency[key] = candidate["payload"][key]
                        dependencies.append(dependency)
                        ownership = _record_ownership(candidate, effective_targets, operation)
                        journal["created_paths"].append(str(ownership))
                        source = _resolve_source(candidate, preimages)
                        if source is not None:
                            imported_plugins.append((candidate, source))
                        continue
                    if candidate["kind"] == "package" and isinstance(
                        candidate["payload"].get("dependency"), (str, dict)
                    ):
                        dependency = candidate["payload"]["dependency"]
                        if isinstance(dependency, str):
                            dependency = {
                                "id": dependency,
                                "targets": effective_targets,
                            }
                        else:
                            dependency = dict(dependency)
                            dependency["targets"] = effective_targets
                        dependencies.append(dependency)
                        continue
                    structured_dependency = _structured_dependency(
                        candidate, effective_targets, preimages
                    )
                    if structured_dependency is not None:
                        dependencies.append(structured_dependency)
                        if candidate["kind"] == "plugin":
                            ownership = _record_ownership(candidate, effective_targets, operation)
                            journal["created_paths"].append(str(ownership))
                            source = _resolve_source(candidate, preimages)
                            if source is not None:
                                imported_plugins.append((candidate, source))
                        continue
                    if candidate["kind"] == "mcp":
                        mcp_dependency = {
                            **candidate["payload"],
                            "name": candidate["name"],
                            "registry": False,
                            "targets": effective_targets,
                        }
                        mcp_dependencies.append(mcp_dependency)
                        if scope == "global":
                            ownership = _record_ownership(candidate, effective_targets, operation)
                            journal["created_paths"].append(str(ownership))
                        continue
                    source = (
                        Path(preimages[candidate["source_preimage_ids"][0]]["absolute_path"])
                        if candidate["payload"].get("import_layout") == "hook-bundle"
                        and candidate["source_preimage_ids"]
                        else _resolve_source(candidate, preimages)
                    )
                    if source is None:
                        raise ImportProtocolError(
                            f"candidate has no importable source: {candidate['id']}"
                        )
                    expected_source = preimages[candidate["source_preimage_ids"][0]]
                    current_source = _preimage(source)
                    if any(
                        current_source[field] != expected_source[field]
                        for field in ("kind", "size", "mode", "content_fingerprint")
                    ):
                        raise ImportProtocolError(f"source changed while applying: {source}")
                    approved_executables = set(item["resolution"].get("approved_executables", []))
                    missing_approvals = set(candidate["executable_paths"]) - approved_executables
                    if missing_approvals:
                        raise ImportProtocolError(
                            "executable approval missing for: "
                            + ", ".join(sorted(missing_approvals))
                        )
                    snapshot = _snapshot(
                        candidate,
                        item,
                        source,
                        expected_source,
                        operation,
                        preimages,
                    )
                    dependencies.append(
                        {
                            "path": str(snapshot),
                            "targets": effective_targets,
                        }
                    )
                    journal["created_paths"].append(str(snapshot))
                    if candidate["kind"] == "plugin":
                        imported_plugins.append((candidate, source))
                if exclusions and scope == "global":
                    _write_exclusions(exclusions)
                for candidate, source in imported_plugins:
                    _capture_plugin_activation(candidate, source, journal)
                journal["phase"] = "packages-staged"
                write_journal(journal)
                manifest_path = _update_manifest(
                    dependencies,
                    mcp_dependencies,
                    path=Path(journal["manifest_path"]),
                )
                journal["phase"] = "manifest-prepared"
                write_journal(journal)
                targets = sorted(
                    effective_install_targets
                    & (set(KNOWN_TARGETS) | set(ClientFactory.supported_clients()))
                )
                install_result = _install_import_manifest(manifest_path, targets, scope)
                journal["phase"] = "installed"
                write_journal(journal)
                _verify_deployment(manifest_path, journal, require_lock=install_result is not None)
                journal["phase"] = "ownership-verified"
                write_journal(journal)
                for candidate, source in imported_plugins:
                    _retire_plugin_activation(candidate, source, journal)
                journal["phase"] = "activation-retired"
                write_journal(journal)
                try:
                    _verify_post_retirement(journal)
                    journal["phase"] = "post-retirement-verified"
                    write_journal(journal)
                    _audit_import(manifest_path)
                except Exception:
                    _restore_retired_activations(journal)
                    raise
                journal["phase"] = "audited"
                write_journal(journal)
                journal["state"] = (
                    "complete" if coordinator == "standalone" else "awaiting-external-commit"
                )
                write_journal(journal)
            except Exception:
                if journal.get("retired_activations"):
                    _restore_retired_activations(journal)
                journal["state"] = "recoverable-partial"
                write_journal(journal)
                raise
        return self.status(operation)

    def status(self, operation_id: str) -> dict[str, Any]:
        journal = read_journal(operation_id)
        if journal is None:
            raise ImportProtocolError(f"unknown import operation: {operation_id}")
        state = journal["state"]
        phase = journal.get("phase", state)
        if state == "awaiting-external-commit":
            next_action = "external-commit-then-finalize"
        elif state == "complete":
            next_action = "none"
        elif phase in {"planned", "backed-up", "packages-staged", "manifest-prepared"}:
            next_action = "rollback"
        else:
            next_action = "resume"
        return {
            "schema_version": SCHEMA_VERSION,
            "operation_id": operation_id,
            "coordinator": journal["coordinator"],
            "state": state,
            "next_action": next_action,
            "finalize_token_required": state == "awaiting-external-commit",
        }

    def resume(self, **kwargs: Any) -> dict[str, Any]:
        plan_path = kwargs["plan_file"]
        plan = json.loads(Path(plan_path).read_text(encoding="utf-8"))
        operation = str(plan.get("operation_id", ""))
        with allow_operation(operation), lifecycle_operation():
            existing = read_journal(operation)
            if existing and existing.get("phase") in {
                "planned",
                "backed-up",
                "packages-staged",
                "manifest-prepared",
            }:
                self.rollback(existing["operation_id"])
                refreshed = read_journal(operation)
                if refreshed:
                    refreshed.pop("backups", None)
                    refreshed["created_paths"] = []
                    write_journal(refreshed)
            return self._apply_locked(**kwargs)

    def finalize(
        self, *, operation_id: str, omni_preimage_set: str, token: bytes
    ) -> dict[str, Any]:
        with allow_operation(operation_id), lifecycle_operation():
            return self._finalize_locked(
                operation_id=operation_id,
                omni_preimage_set=omni_preimage_set,
                token=token,
            )

    def _finalize_locked(
        self, *, operation_id: str, omni_preimage_set: str, token: bytes
    ) -> dict[str, Any]:
        journal = read_journal(operation_id)
        if journal is None:
            raise ImportProtocolError(f"unknown import operation: {operation_id}")
        if (
            journal["coordinator"] != "omni-v24"
            or journal["omni_preimage_set"] != omni_preimage_set
        ):
            raise ImportProtocolError("finalize operation/preimage mismatch")
        if not hmac.compare_digest(journal["token_hash"] or "", hashlib.sha256(token).hexdigest()):
            raise ImportProtocolError("finalize capability mismatch")
        if journal["state"] == "complete":
            return self.status(operation_id)
        if journal["state"] != "awaiting-external-commit":
            raise ImportProtocolError(f"operation cannot be finalized from {journal['state']}")
        with allow_operation(operation_id), lifecycle_operation():
            journal["state"] = "complete"
            write_journal(journal)
        return self.status(operation_id)

    def rollback(self, operation_id: str) -> dict[str, Any]:
        with allow_operation(operation_id), lifecycle_operation():
            return self._rollback_locked(operation_id)

    def _rollback_locked(self, operation_id: str) -> dict[str, Any]:
        journal = read_journal(operation_id)
        if journal is None:
            raise ImportProtocolError(f"unknown import operation: {operation_id}")
        phase = journal.get("phase", journal["state"])
        if (
            phase not in {"planned", "backed-up", "packages-staged", "manifest-prepared"}
            and journal["state"] != "rolled-back"
        ):
            raise ImportProtocolError(f"operation is resume-only from {phase}")
        with allow_operation(operation_id), lifecycle_operation():
            if journal.get("retired_activations"):
                _restore_retired_activations(journal)
            for raw in reversed(journal.get("created_paths", [])):
                path = Path(raw).resolve(strict=False)
                imported = (Path.home() / ".apm" / "imported").resolve(strict=False)
                if path.is_relative_to(imported) and path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
            for record in journal.get("backups", []):
                managed_path = Path(record["path"])
                if record["existed"] and record["backup"]:
                    if record.get("encoding") == "base64":
                        raw = base64.b64decode(
                            Path(record["backup"]).read_text(encoding="utf-8").strip(),
                            validate=True,
                        )
                        restore_file_bytes(managed_path, raw, int(record.get("mode") or 0o600))
                    else:
                        managed_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                        atomic_write_text(
                            managed_path,
                            Path(record["backup"]).read_text(encoding="utf-8"),
                            new_file_mode=0o600,
                        )
                        harden_path(managed_path)
                elif managed_path.is_file() and not managed_path.is_symlink():
                    managed_path.unlink()
            journal["state"] = "rolled-back"
            write_journal(journal)
        return self.status(operation_id)

    def cleanup(self, operation_id: str) -> dict[str, Any]:
        with allow_operation(operation_id), lifecycle_operation():
            return self._cleanup_locked(operation_id)

    def _cleanup_locked(self, operation_id: str) -> dict[str, Any]:
        journal = read_journal(operation_id)
        if journal is None or journal["state"] not in {"complete", "rolled-back"}:
            raise ImportProtocolError("cleanup requires a completed or rolled-back operation")
        root = journal_root(operation_id)
        removable = [
            Path(record["backup"]) for record in journal.get("backups", []) if record.get("backup")
        ]
        removable.extend(
            Path(record["backup"])
            for record in journal.get("retired_activations", [])
            if record.get("backup")
        )
        for path in removable:
            contained = root.contained(path.relative_to(root.path))
            if contained.is_file() and not contained.is_symlink():
                contained.unlink()
        journal["cleaned"] = True
        write_journal(journal)
        return self.status(operation_id)

    def list_exclusions(self) -> list[dict[str, Any]]:
        entries = _load_exclusions()
        return [entries[key] for key in sorted(entries)]

    def remove_exclusion(self, exclusion_id: str) -> list[dict[str, Any]]:
        with lifecycle_operation():
            entries = _load_exclusions()
            entries.pop(exclusion_id, None)
            _write_exclusions(entries)
            return [entries[key] for key in sorted(entries)]
