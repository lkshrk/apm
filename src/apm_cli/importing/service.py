"""Deterministic native-state import protocol."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import re
import shlex
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

import yaml

from apm_cli.install.locking import lifecycle_operation
from apm_cli.integration.targets import KNOWN_TARGETS
from apm_cli.utils.atomic_io import atomic_write_text
from apm_cli.utils.yaml_io import dump_yaml_roundtrip, load_yaml, yaml_to_str

from .journal import allow_operation, journal_root, read_journal, write_journal
from .secure import SecureRoot, harden_path, restore_file_bytes

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
_ENV_PLACEHOLDER = re.compile(r"^(?:\$\{(?:env:)?[A-Z_][A-Z0-9_]*\}|<[A-Z_][A-Z0-9_]*>)$")
_SECRET_KEYS = frozenset({"token", "password", "secret", "authorization", "api_key", "apikey"})
_MAX_SNAPSHOT_FILES = 10_000
_MAX_SNAPSHOT_BYTES = 100 * 1024 * 1024
_UNMANAGED_NATIVE_CLIENTS = (
    "copilot",
    "cursor",
    "kiro",
    "opencode",
    "gemini",
    "grok-build",
    "antigravity",
    "windsurf",
    "openclaw",
    "hermes",
    "copilot-app",
)
_EMPTY_RESOLUTION = {
    "decision": "",
    "selected_origin_id": "",
    "approved_targets": [],
    "env_bindings": {},
    "approved_executables": [],
}


class ImportProtocolError(RuntimeError):
    """Strict protocol or stale-plan error."""


@dataclass(frozen=True)
class _Root:
    id: str
    target: str
    path: Path


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_entries(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    file_count = 0
    byte_count = 0
    for item in sorted(path.rglob("*")):
        relative = item.relative_to(path).as_posix()
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ImportProtocolError(f"symlink is not importable: {item}")
        if item.is_dir():
            entries.append({"path": relative, "kind": "dir", "mode": stat.S_IMODE(info.st_mode)})
        elif item.is_file():
            file_count += 1
            byte_count += info.st_size
            if file_count > _MAX_SNAPSHOT_FILES or byte_count > _MAX_SNAPSHOT_BYTES:
                raise ImportProtocolError(
                    f"local snapshot exceeds {_MAX_SNAPSHOT_FILES} files or "
                    f"{_MAX_SNAPSHOT_BYTES} bytes: {path}"
                )
            entries.append(
                {
                    "path": relative,
                    "kind": "file",
                    "size": info.st_size,
                    "mode": stat.S_IMODE(info.st_mode),
                    "hash": _file_hash(item),
                }
            )
        else:
            raise ImportProtocolError(f"special file is not importable: {item}")
    return entries


def _preimage(path: Path) -> dict[str, Any]:
    resolved = path.expanduser().resolve(strict=True)
    info = resolved.stat()
    if resolved.is_symlink():
        raise ImportProtocolError(f"source is a symlink: {resolved}")
    if resolved.is_dir():
        entries = _tree_entries(resolved)
        size = sum(int(entry.get("size", 0)) for entry in entries)
        fingerprint = _digest(entries)
        kind = "directory"
    elif resolved.is_file():
        size = info.st_size
        if size > _MAX_SNAPSHOT_BYTES:
            raise ImportProtocolError(
                f"local snapshot exceeds {_MAX_SNAPSHOT_BYTES} bytes: {resolved}"
            )
        fingerprint = _file_hash(resolved)
        kind = "file"
    else:
        raise ImportProtocolError(f"unsupported source type: {resolved}")
    return {
        "id": _digest({"path": str(resolved), "kind": kind})[:24],
        "absolute_path": str(resolved),
        "kind": kind,
        "size": size,
        "mode": stat.S_IMODE(info.st_mode),
        "content_fingerprint": fingerprint,
    }


def _sanitize(value: Any, *, secret_context: bool = False) -> tuple[Any, bool]:
    blocked = False
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            lower = str(key).lower()
            sensitive = (
                secret_context
                or lower in {"env", "headers", "http_headers"}
                or lower in _SECRET_KEYS
            )
            sanitized, child_blocked = _sanitize(child, secret_context=sensitive)
            result[str(key)] = sanitized
            blocked = blocked or child_blocked
        return result, blocked
    if isinstance(value, list):
        result = []
        for child in value:
            sanitized, child_blocked = _sanitize(child, secret_context=secret_context)
            result.append(sanitized)
            blocked = blocked or child_blocked
        return result, blocked
    if isinstance(value, str):
        parsed = urlsplit(value)
        if parsed.username or parsed.password:
            host = parsed.hostname or ""
            if parsed.port:
                host += f":{parsed.port}"
            return urlunsplit(
                (parsed.scheme, host, parsed.path, parsed.query, parsed.fragment)
            ), True
        if secret_context and value and not _ENV_PLACEHOLDER.fullmatch(value):
            return {"blocked": "literal-secret"}, True
    return value, False


def _candidate(
    root: _Root, path: Path, kind: str, name: str, payload: Any | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    preimage = _preimage(path)
    relative = path.resolve().relative_to(root.path.resolve()).as_posix()
    executables: list[str] = []
    paths = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file()]
    for item in paths:
        if stat.S_IMODE(item.stat().st_mode) & 0o111:
            executables.append(
                item.resolve()
                .relative_to(path.resolve() if path.is_dir() else root.path.resolve())
                .as_posix()
            )
    local_reference = payload is None
    clean_payload, blocked = _sanitize(payload or {"source": "secured-path"})
    content = preimage["content_fingerprint"] if local_reference else _digest(clean_payload)
    candidate_id = _digest({"root": root.id, "kind": kind, "name": name, "path": relative})[:32]
    return preimage, {
        "id": candidate_id,
        "kind": kind,
        "name": name,
        "root_id": root.id,
        "source_handle": f"{root.id}:{relative}",
        "source_target": [root.target],
        "provenance": "local-only",
        "payload": clean_payload,
        "content_fingerprint": content,
        "source_preimage_ids": [preimage["id"]],
        "executable_paths": sorted(executables),
        "secret_blocked": blocked,
    }


def _root_path(target: str) -> Path:
    if target == "claude":
        return (
            Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude"))
            .expanduser()
            .resolve(strict=False)
        )
    if target == "codex":
        return (
            Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
            .expanduser()
            .resolve(strict=False)
        )
    raise ImportProtocolError(f"unsupported source target: {target}")


def _user_target_root(target: str) -> Path | None:
    profile = KNOWN_TARGETS[target].for_scope(user_scope=True)
    if profile is None:
        return None
    if profile.resolved_deploy_root is not None:
        return profile.resolved_deploy_root.resolve(strict=False)
    root = Path(profile.root_dir).expanduser()
    return (root if root.is_absolute() else Path.home() / root).resolve(strict=False)


def _discover_unmanaged_clients() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    candidates: list[dict[str, Any]] = []
    preimages: list[dict[str, Any]] = []
    for target in _UNMANAGED_NATIVE_CLIENTS:
        root = _user_target_root(target)
        if root is None or not root.exists():
            continue
        if root.is_dir():
            try:
                if next(root.iterdir(), None) is None:
                    continue
            except OSError as exc:
                raise ImportProtocolError(f"cannot inspect {target} client root") from exc
        info = root.lstat()
        fingerprint = _digest({"unmanaged_client": target, "root": str(root)})
        preimage_id = _digest({"path": str(root), "kind": "unmanaged-client-root"})[:24]
        preimage = {
            "id": preimage_id,
            "absolute_path": str(root),
            "kind": "directory" if root.is_dir() else "file",
            "size": info.st_size,
            "mode": stat.S_IMODE(info.st_mode),
            "content_fingerprint": fingerprint,
        }
        candidate = {
            "id": _digest({"unmanaged_client": target, "root": str(root)})[:32],
            "kind": "unsupported",
            "name": target,
            "root_id": f"{target}-config",
            "source_handle": f"unmanaged-client:{target}",
            "source_target": [target],
            "provenance": "native-unmanaged",
            "payload": {
                "client": target,
                "source": "secured-path",
                "unsupported_reason": "native-import-decoder-unavailable",
                "leave_unmanaged_available": True,
            },
            "content_fingerprint": fingerprint,
            "source_preimage_ids": [preimage_id],
            "executable_paths": [],
            "secret_blocked": False,
        }
        preimages.append(preimage)
        candidates.append(candidate)
    return candidates, preimages


def _load_structured(path: Path) -> Any:
    if path.suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    if path.suffix == ".toml":
        try:
            import tomllib
        except ImportError:  # pragma: no cover - Python 3.10
            import tomli as tomllib
        return tomllib.loads(path.read_text(encoding="utf-8"))
    return None


def _hook_scripts(value: Any, *, base: Path, root: Path) -> list[Path]:
    found: set[Path] = set()
    if isinstance(value, dict):
        for child in value.values():
            found.update(_hook_scripts(child, base=base, root=root))
    elif isinstance(value, list):
        for child in value:
            found.update(_hook_scripts(child, base=base, root=root))
    elif isinstance(value, str):
        try:
            tokens = shlex.split(value, posix=os.name != "nt")
        except ValueError:
            tokens = []
        if tokens:
            candidate = Path(tokens[0]).expanduser()
            if not candidate.is_absolute():
                candidate = base / candidate
            resolved = candidate.resolve(strict=False)
            if resolved.is_file() and resolved.is_relative_to(root.resolve(strict=False)):
                found.add(resolved)
    return sorted(found)


def _discover_target(target: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    root_path = _root_path(target)
    root = _Root(f"{target}-config", target, root_path)
    candidates: list[dict[str, Any]] = []
    preimages: list[dict[str, Any]] = []
    if not root_path.is_dir() and target != "codex":
        return candidates, preimages

    layouts: list[tuple[str, str, str]]
    if target == "claude":
        layouts = [
            ("rules", "*.md", "instruction"),
            ("agents", "*.md", "agent"),
            ("commands", "*.md", "command"),
            ("skills", "*/SKILL.md", "skill"),
            ("hooks", "*.json", "hook"),
        ]
    else:
        layouts = [("agents", "*.toml", "agent"), ("skills", "*/SKILL.md", "skill")]
    for directory, pattern, kind in layouts:
        for found in sorted((root_path / directory).glob(pattern)):
            source = found.parent if kind == "skill" else found
            name = source.name if source.is_dir() else source.stem
            payload = _load_structured(source) if kind == "hook" else None
            preimage, candidate = _candidate(root, source, kind, name, payload)
            preimages.append(preimage)
            candidates.append(candidate)
            if kind == "hook" and payload is not None:
                for script in _hook_scripts(payload, base=source.parent, root=root_path):
                    script_preimage, script_candidate = _candidate(
                        root, script, "hook", f"{name}-{script.stem}"
                    )
                    preimages.append(script_preimage)
                    candidates.append(script_candidate)
    if target == "claude":
        claude_md = root_path / "CLAUDE.md"
        if claude_md.is_file():
            preimage, candidate = _candidate(
                root,
                claude_md,
                "instruction",
                "compiled-claude-md",
            )
            preimages.append(preimage)
            candidates.append(candidate)

    if target == "codex":
        shared = _Root(
            "shared-agent-skills", target, (Path.home() / ".agents").resolve(strict=False)
        )
        for found in sorted((shared.path / "skills").glob("*/SKILL.md")):
            preimage, candidate = _candidate(shared, found.parent, "skill", found.parent.name)
            preimages.append(preimage)
            candidates.append(candidate)
        hook_path = root_path / "hooks.json"
        if hook_path.is_file():
            hook_payload = _load_structured(hook_path)
            preimage, candidate = _candidate(root, hook_path, "hook", "codex-hooks", hook_payload)
            preimages.append(preimage)
            candidates.append(candidate)
            for script in _hook_scripts(hook_payload, base=root_path, root=root_path):
                script_preimage, script_candidate = _candidate(
                    root, script, "hook", f"codex-{script.stem}"
                )
                preimages.append(script_preimage)
                candidates.append(script_candidate)

    config_path = root_path / ("settings.json" if target == "claude" else "config.toml")
    if config_path.is_file():
        data = _load_structured(config_path) or {}
        servers = data.get("mcpServers", {}) if target == "claude" else data.get("mcp_servers", {})
        for name, payload in sorted(servers.items()):
            preimage, candidate = _candidate(root, config_path, "mcp", str(name), payload)
            preimages.append(preimage)
            candidates.append(candidate)
        if target == "claude" and data.get("hooks"):
            preimage, candidate = _candidate(
                root, config_path, "hook", "settings-hooks", data["hooks"]
            )
            preimages.append(preimage)
            candidates.append(candidate)
            for script in _hook_scripts(data["hooks"], base=root_path, root=root_path):
                script_preimage, script_candidate = _candidate(
                    root, script, "hook", f"settings-{script.stem}"
                )
                preimages.append(script_preimage)
                candidates.append(script_candidate)

    installed_path = root_path / "plugins" / "installed_plugins.json"
    installed_data = _load_structured(installed_path) if installed_path.is_file() else {}
    installed_entries = (
        installed_data.get("plugins", installed_data) if isinstance(installed_data, dict) else {}
    )
    installed_refs: dict[Path, str] = {}
    if isinstance(installed_entries, dict):
        for ref, records in installed_entries.items():
            record_list = records if isinstance(records, list) else [records]
            for record in record_list:
                if isinstance(record, dict) and record.get("installPath"):
                    installed_refs[
                        Path(str(record["installPath"])).expanduser().resolve(strict=False)
                    ] = str(ref)

    plugin_roots: set[Path] = set()
    for marker in (".claude-plugin/plugin.json", ".codex-plugin/plugin.json"):
        for manifest in (root_path / "plugins").glob(f"**/{marker}"):
            plugin_roots.add(manifest.parent.parent.resolve())
    for plugin_path in sorted(plugin_roots):
        manifest_paths = [
            plugin_path / ".claude-plugin" / "plugin.json",
            plugin_path / ".codex-plugin" / "plugin.json",
        ]
        manifest = next(path for path in manifest_paths if path.is_file())
        metadata = _load_structured(manifest) or {}
        name = str(metadata.get("name") or plugin_path.name)
        plugin_root = _Root(
            f"{target}-plugin-{_digest(str(plugin_path))[:12]}", target, plugin_path
        )
        preimage, candidate = _candidate(
            plugin_root,
            plugin_path,
            "plugin",
            name,
        )
        marketplace_ref = installed_refs.get(plugin_path)
        if marketplace_ref and "@" in marketplace_ref:
            plugin_name, marketplace_name = marketplace_ref.rsplit("@", 1)
            candidate["provenance"] = "marketplace"
            candidate["payload"] = {
                "plugin": plugin_name,
                "marketplace": marketplace_name,
            }
        preimages.append(preimage)
        candidates.append(candidate)

    if installed_path.is_file():
        entries = installed_entries
        if isinstance(entries, dict):
            for name, records in sorted(entries.items()):
                record_list = records if isinstance(records, list) else [records]
                paths = [
                    Path(str(record.get("installPath"))).expanduser().resolve(strict=False)
                    for record in record_list
                    if isinstance(record, dict) and record.get("installPath")
                ]
                if paths and any(path in plugin_roots for path in paths):
                    continue
                preimage, candidate = _candidate(
                    root,
                    installed_path,
                    "plugin",
                    str(name),
                    {"unsupported_reason": "plugin-install-path-missing"},
                )
                preimages.append(preimage)
                candidates.append(candidate)

    marketplace_path = root_path / "plugins" / "known_marketplaces.json"
    if marketplace_path.is_file():
        marketplace_data = _load_structured(marketplace_path) or {}
        entries = marketplace_data.get("marketplaces", marketplace_data)
        if isinstance(entries, dict):
            iterator = sorted(entries.items())
        elif isinstance(entries, list):
            iterator = [
                (str(entry.get("name", f"marketplace-{index}")), entry)
                for index, entry in enumerate(entries)
                if isinstance(entry, dict)
            ]
        else:
            iterator = []
        for name, payload in iterator:
            preimage, candidate = _candidate(root, marketplace_path, "marketplace", name, payload)
            preimages.append(preimage)
            candidates.append(candidate)
    if target == "codex":
        agents_md = root_path / "AGENTS.md"
        if agents_md.is_file():
            preimage, candidate = _candidate(
                root,
                agents_md,
                "instruction",
                "compiled-agents-md",
                {"unsupported_reason": "codex-instructions-compile-only"},
            )
            preimages.append(preimage)
            candidates.append(candidate)
    return candidates, preimages


def _load_exclusions() -> dict[str, dict[str, Any]]:
    path = Path.home() / ".apm" / "import-exclusions.yml"
    if not path.is_file() or path.is_symlink():
        if path.is_symlink():
            raise ImportProtocolError("import exclusion ledger is a symlink")
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
        raise ImportProtocolError("malformed import exclusion ledger") from exc
    if (
        not isinstance(data, dict)
        or set(data) != {"schema_version", "entries"}
        or data["schema_version"] != 1
        or not isinstance(data["entries"], list)
    ):
        raise ImportProtocolError("malformed import exclusion ledger")
    required = {"id", "kind", "name", "root_id", "targets", "content_fingerprint"}
    result = {}
    for entry in data["entries"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != required
            or not isinstance(entry["targets"], list)
        ):
            raise ImportProtocolError("malformed import exclusion ledger entry")
        result[str(entry["id"])] = entry
    return result


def _exclusion_entry(candidate: dict[str, Any], targets: list[str]) -> dict[str, Any]:
    return {
        "id": candidate["id"],
        "kind": candidate["kind"],
        "name": candidate["name"],
        "root_id": candidate["root_id"],
        "targets": sorted(targets),
        "content_fingerprint": candidate["content_fingerprint"],
    }


def _exclusion_matches(
    entry: dict[str, Any], candidate: dict[str, Any], targets: list[str]
) -> bool:
    return all(
        (
            entry["id"] == candidate["id"],
            entry["kind"] == candidate["kind"],
            entry["name"] == candidate["name"],
            entry["root_id"] == candidate["root_id"],
            sorted(entry["targets"]) == sorted(targets),
            entry["content_fingerprint"] == candidate["content_fingerprint"],
        )
    )


def _write_exclusions(entries: dict[str, dict[str, Any]]) -> None:
    root = SecureRoot(Path.home() / ".apm").ensure()
    payload = {"schema_version": 1, "entries": [entries[key] for key in sorted(entries)]}
    root.write_text("import-exclusions.yml", yaml_to_str(payload, sort_keys=False))


def _managed_ids() -> set[str]:
    root = Path.home() / ".apm" / "imported"
    result: set[str] = set()
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
        "scope",
        "sources",
        "candidate_set_id",
        "source_preimages",
        "candidates",
    }
    if not isinstance(data, dict) or set(data) != required:
        raise ImportProtocolError(f"candidate schema fields mismatch: expected {sorted(required)}")
    if data["schema_version"] != SCHEMA_VERSION or data["coordinator"] not in COORDINATORS:
        raise ImportProtocolError("unsupported candidate schema/coordinator")
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
    expected = _digest(
        {
            "sources": data["sources"],
            "preimages": data["source_preimages"],
            "candidates": data["candidates"],
        }
    )
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


def _apm_state_fingerprint() -> str:
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
    exclusions = _load_exclusions()
    managed = _managed_ids()
    name_fingerprints: dict[tuple[str, str], set[str]] = {}
    name_candidates: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for candidate in candidate_data["candidates"]:
        name_key = (candidate["kind"], candidate["name"])
        name_fingerprints.setdefault(name_key, set()).add(candidate["content_fingerprint"])
        name_candidates.setdefault(name_key, []).append(candidate)
    seen: set[tuple[str, str, str]] = set()
    grouped: set[str] = set()
    items = []
    blockers = []
    for candidate in sorted(candidate_data["candidates"], key=lambda value: value["id"]):
        name_key = (candidate["kind"], candidate["name"])
        if len(name_fingerprints[name_key]) > 1:
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
        elif candidate["executable_paths"]:
            classification, action, reasons = (
                "needs-choice",
                "snapshot",
                [
                    "executable-approval-required",
                    *(f"executable:{path}" for path in sorted(candidate["executable_paths"])),
                ],
            )
        elif candidate["id"] in managed:
            classification, action, reasons = (
                "already-managed",
                "reuse",
                ["managed-import-metadata"],
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
            "apm_state": _apm_state_fingerprint(),
        }
    )
    counts: dict[str, int] = {}
    for item in items:
        counts[item["classification"]] = counts.get(item["classification"], 0) + 1
    plan = {
        "schema_version": SCHEMA_VERSION,
        "coordinator": candidate_data["coordinator"],
        "scope": candidate_data["scope"],
        "sources": candidate_data["sources"],
        "candidate_set_id": candidate_data["candidate_set_id"],
        "inventory_fingerprint": inventory,
        "items": items,
        "summary": counts,
        "warnings": [],
        "blockers": blockers,
    }
    immutable = {**plan, "items": [{**item, "resolution": _EMPTY_RESOLUTION} for item in items]}
    plan_id = _digest(immutable)
    resolution_id = _resolution_identity(items)
    operation = _digest(
        {
            "candidate_set_id": candidate_data["candidate_set_id"],
            "plan_id": plan_id,
            "resolution_id": resolution_id,
        }
    )[:32]
    return {
        **plan,
        "plan_id": plan_id,
        "resolution_id": resolution_id,
        "operation_id": operation,
    }


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
        "scope",
        "sources",
        "candidate_set_id",
        "inventory_fingerprint",
        "items",
        "summary",
        "warnings",
        "blockers",
    }
    if not isinstance(data, dict) or set(data) != required:
        raise ImportProtocolError("plan schema fields mismatch")
    if data["schema_version"] != SCHEMA_VERSION or data["coordinator"] != candidates["coordinator"]:
        raise ImportProtocolError("plan coordinator/schema mismatch")
    if data["candidate_set_id"] != candidates["candidate_set_id"]:
        raise ImportProtocolError("plan is bound to a different candidate set")
    resolutions = {item["id"]: item.get("resolution", {}) for item in data["items"]}
    expected = _plan(candidates, resolutions)
    if _canonical(data) != _canonical(expected):
        raise ImportProtocolError("reviewed plan immutable fields or resolution identity changed")
    return data


def _validate_plan_identity(data: dict[str, Any]) -> None:
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
    if candidate["payload"] == {"source": "secured-path"}:
        return _preimage(staged_source)["content_fingerprint"]
    payload = _load_structured(staged_source)
    clean, _ = _sanitize(payload)
    return _digest(clean)


def _snapshot(
    candidate: dict[str, Any],
    item: dict[str, Any],
    source: Path,
    expected_source: dict[str, Any],
    operation_id: str,
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
        approved = set(item["resolution"].get("approved_executables", []))
        if kind == "plugin":
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
        if kind == "plugin":
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


def _update_manifest(dependencies: list[Any], mcp_dependencies: list[dict[str, Any]]) -> Path:
    path = Path.home() / ".apm" / "apm.yml"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = load_yaml(path) if path.is_file() else {"name": "global", "version": "1.0.0"}
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
    source = payload.get("source", payload)
    repo = source.get("repo") if isinstance(source, dict) else None
    owner = source.get("owner") if isinstance(source, dict) else None
    if isinstance(repo, str) and "/" in repo and not owner:
        owner, repo = repo.split("/", 1)
    if not isinstance(owner, str) or not isinstance(repo, str):
        raise ImportProtocolError(f"marketplace {name} has no canonical owner/repo")
    path = Path.home() / ".apm" / "marketplaces.json"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {"marketplaces": []}
    entries = data.setdefault("marketplaces", [])
    entry = {"name": name, "owner": owner, "repo": repo}
    matching = [item for item in entries if item.get("name") == name]
    if matching and matching != [entry]:
        raise ImportProtocolError(f"marketplace name collision: {name}")
    if not matching:
        entries.append(entry)
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
    target = candidate["source_target"][0]
    config = _root_path(target) / "plugins" / "installed_plugins.json"
    if not config.is_file() or config.is_symlink():
        return
    raw = config.read_bytes()
    data = json.loads(raw)
    if not _contains_text(data, str(source)):
        return
    if any(
        record["path"] == str(config.resolve()) for record in journal.get("retired_activations", [])
    ):
        return
    backup_name = f"activation-{_digest(str(config))[:16]}.base64"
    backup = journal_root(journal["operation_id"], create=True).write_text(
        backup_name, base64.b64encode(raw).decode("ascii") + "\n"
    )
    journal.setdefault("retired_activations", []).append(
        {
            "path": str(config.resolve()),
            "backup": str(backup),
            "source": str(source),
            "mode": stat.S_IMODE(config.stat().st_mode),
            "hash": hashlib.sha256(raw).hexdigest(),
        }
    )


def _retire_plugin_activation(
    candidate: dict[str, Any], source: Path, journal: dict[str, Any]
) -> None:
    target = candidate["source_target"][0]
    config = _root_path(target) / "plugins" / "installed_plugins.json"
    if not config.is_file() or config.is_symlink():
        return
    data = json.loads(config.read_text(encoding="utf-8"))
    if not _contains_text(data, str(source)):
        return
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


def _install_manifest(path: Path, targets: list[str]) -> Any:
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
    with contextlib.chdir(path.parent):
        result = InstallService().run(
            InstallRequest(
                apm_package=package,
                logger=logger,
                scope=InstallScope.USER,
                target=sorted(set(targets)),
            )
        )
        run_service_integrations(
            SimpleNamespace(
                project_root=path.parent,
                scope=InstallScope.USER,
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


def _verify_deployment(
    manifest_path: Path, journal: dict[str, Any], *, require_lock: bool = True
) -> None:
    from apm_cli.models.apm_package import APMPackage

    package = APMPackage.from_apm_yml(manifest_path)
    if (
        require_lock
        and package.get_apm_dependencies()
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
    ) -> dict[str, Any]:
        if coordinator not in COORDINATORS:
            raise ImportProtocolError(f"unsupported coordinator: {coordinator}")
        if candidate_file and candidate_file.is_file():
            _validate_protocol_file(candidate_file)
            data = _validate_candidate_envelope(
                json.loads(candidate_file.read_text(encoding="utf-8"))
            )
            if data["coordinator"] != coordinator:
                raise ImportProtocolError("candidate coordinator mismatch")
            if sources:
                candidates_by_id = {item["id"]: item for item in data["candidates"]}
                preimages_by_id = {item["id"]: item for item in data["source_preimages"]}
                for source in sorted(set(sources)):
                    discovered, preimages = _discover_target(source)
                    candidates_by_id.update((item["id"], item) for item in discovered)
                    preimages_by_id.update((item["id"], item) for item in preimages)
                unmanaged, unmanaged_preimages = _discover_unmanaged_clients()
                candidates_by_id.update((item["id"], item) for item in unmanaged)
                preimages_by_id.update((item["id"], item) for item in unmanaged_preimages)
                data["sources"] = sorted(set(data["sources"]) | set(sources))
                data["source_preimages"] = sorted(
                    preimages_by_id.values(), key=lambda value: value["id"]
                )
                data["candidates"] = sorted(
                    candidates_by_id.values(), key=lambda value: value["id"]
                )
                data["candidate_set_id"] = _digest(
                    {
                        "sources": data["sources"],
                        "preimages": data["source_preimages"],
                        "candidates": data["candidates"],
                    }
                )
                _write_json(candidate_file, data)
        else:
            all_candidates: list[dict[str, Any]] = []
            all_preimages: list[dict[str, Any]] = []
            normalized_sources = sorted(set(sources))
            for source in normalized_sources:
                candidates, preimages = _discover_target(source)
                all_candidates.extend(candidates)
                all_preimages.extend(preimages)
            unmanaged, unmanaged_preimages = _discover_unmanaged_clients()
            all_candidates.extend(unmanaged)
            all_preimages.extend(unmanaged_preimages)
            preimages_by_id = {item["id"]: item for item in all_preimages}
            data = {
                "schema_version": SCHEMA_VERSION,
                "coordinator": coordinator,
                "scope": "global",
                "sources": normalized_sources,
                "candidate_set_id": "",
                "source_preimages": sorted(preimages_by_id.values(), key=lambda value: value["id"]),
                "candidates": sorted(all_candidates, key=lambda value: value["id"]),
            }
            data["candidate_set_id"] = _digest(
                {
                    "sources": data["sources"],
                    "preimages": data["source_preimages"],
                    "candidates": data["candidates"],
                }
            )
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
            "state": "recoverable-partial",
            "phase": "planned",
            "candidate_set_id": candidates["candidate_set_id"],
            "inventory_fingerprint": plan["inventory_fingerprint"],
            "plan_id": plan["plan_id"],
            "resolution_id": plan["resolution_id"],
            "omni_preimage_set": omni_preimage_set,
            "token_hash": hashlib.sha256(token).hexdigest() if token else None,
            "created_paths": [],
            "manifest_path": str(Path.home() / ".apm" / "apm.yml"),
            "cleaned": False,
        }
        with allow_operation(operation), lifecycle_operation():
            try:
                write_journal(journal)
                if "backups" not in journal:
                    journal["backups"] = []
                    for index, managed_path in enumerate(
                        (
                            Path(journal["manifest_path"]),
                            Path.home() / ".apm" / "marketplaces.json",
                            Path.home() / ".apm" / "import-exclusions.yml",
                        )
                    ):
                        record = {
                            "path": str(managed_path),
                            "existed": managed_path.is_file(),
                            "backup": None,
                        }
                        if managed_path.is_file():
                            backup = journal_root(operation, create=True).write_text(
                                f"managed-{index}.backup",
                                managed_path.read_text(encoding="utf-8"),
                            )
                            record["backup"] = str(backup)
                        journal["backups"].append(record)
                journal["phase"] = "backed-up"
                write_journal(journal)
                by_id = {item["id"]: item for item in candidates["candidates"]}
                preimages = {item["id"]: item for item in candidates["source_preimages"]}
                dependencies: list[Any] = []
                mcp_dependencies: list[dict[str, Any]] = []
                exclusions = _load_exclusions()
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
                    effective_install_targets.update(effective_targets)
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
                    if candidate["kind"] == "marketplace":
                        _register_marketplace(candidate["name"], candidate["payload"])
                        continue
                    if candidate["kind"] == "plugin" and candidate["provenance"] == "marketplace":
                        dependencies.append(
                            {
                                "name": candidate["payload"]["plugin"],
                                "marketplace": candidate["payload"]["marketplace"],
                                "targets": effective_targets,
                            }
                        )
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
                        continue
                    if candidate["kind"] == "mcp":
                        mcp_dependency = {
                            **candidate["payload"],
                            "name": candidate["name"],
                            "registry": False,
                        }
                        mcp_dependencies.append(mcp_dependency)
                        ownership = _record_ownership(candidate, effective_targets, operation)
                        journal["created_paths"].append(str(ownership))
                        continue
                    source = _resolve_source(candidate, preimages)
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
                    snapshot = _snapshot(candidate, item, source, expected_source, operation)
                    dependencies.append(
                        {
                            "path": str(snapshot),
                            "targets": effective_targets,
                        }
                    )
                    journal["created_paths"].append(str(snapshot))
                    if candidate["kind"] == "plugin":
                        imported_plugins.append((candidate, source))
                if exclusions:
                    _write_exclusions(exclusions)
                for candidate, source in imported_plugins:
                    _capture_plugin_activation(candidate, source, journal)
                journal["phase"] = "packages-staged"
                write_journal(journal)
                manifest_path = _update_manifest(dependencies, mcp_dependencies)
                journal["phase"] = "manifest-prepared"
                write_journal(journal)
                targets = sorted(effective_install_targets & {"claude", "codex"})
                install_result = _install_manifest(manifest_path, targets)
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
            for raw in reversed(journal.get("created_paths", [])):
                path = Path(raw).resolve(strict=False)
                imported = (Path.home() / ".apm" / "imported").resolve(strict=False)
                if path.is_relative_to(imported) and path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
            for record in journal.get("backups", []):
                managed_path = Path(record["path"])
                if record["existed"] and record["backup"]:
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
