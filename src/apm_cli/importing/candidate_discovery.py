"""Native client candidate discovery for import."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import yaml

from apm_cli.integration.targets import KNOWN_TARGETS
from apm_cli.utils.yaml_io import yaml_to_str

from .compiled_instructions import adopt_compiled_instruction
from .discovery import NativeResource, discover_filesystem_resources, path_boundary_error
from .mcp_discovery import discover_mcp_sources
from .plugin_discovery import discover_plugin_state
from .secure import SecureRoot
from .special_resources import (
    discover_canvas_resources,
    discover_copilot_app_workflows,
    discover_cowork_resources,
    snapshot_hook,
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


def _sensitive_name(value: object) -> bool:
    normalized = str(value).lower().replace("-", "_")
    return normalized in _SECRET_KEYS or any(
        normalized.endswith(f"_{suffix}") for suffix in _SECRET_KEYS
    )


def _ownership_path_key(path: str | Path, *, home: Path | None = None) -> str:
    """Normalize lockfile paths across slash direction and Windows case rules."""
    candidate = Path(str(path).replace("\\", "/")).expanduser()
    if not candidate.is_absolute():
        candidate = (home or Path.home()) / candidate
    return os.path.normcase(os.path.normpath(str(candidate.resolve(strict=False))))


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


def _canonical_project_root(path: Path | None) -> Path:
    if path is None:
        raise ImportProtocolError("project import requires a project root; rescan")
    expanded = path.expanduser()
    if not expanded.is_absolute():
        raise ImportProtocolError("project root must be an absolute canonical path")
    absolute = Path(os.path.abspath(expanded))
    try:
        resolved = expanded.resolve(strict=True)
    except OSError as exc:
        raise ImportProtocolError(f"project root is missing: {expanded}") from exc
    if resolved != absolute or not resolved.is_dir() or expanded.is_symlink():
        raise ImportProtocolError(
            f"project root must be a canonical non-symlink directory: {expanded}"
        )
    return resolved


def _scope_identity(data: dict[str, Any]) -> tuple[str, Path | None]:
    scope = data.get("scope", "global")
    if scope == "global":
        if data.get("project_root") is not None:
            raise ImportProtocolError("global import cannot declare a project root")
        return scope, None
    if scope != "project":
        raise ImportProtocolError(f"unsupported import scope: {scope}")
    raw_root = data.get("project_root")
    if not isinstance(raw_root, str):
        raise ImportProtocolError("project import plan is missing project_root; rescan")
    root = _canonical_project_root(Path(raw_root))
    if raw_root != str(root):
        raise ImportProtocolError("project_root is not canonical; rescan")
    return scope, root


def _candidate_set_identity(data: dict[str, Any]) -> str:
    identity = {
        "sources": data["sources"],
        "preimages": data["source_preimages"],
        "candidates": data["candidates"],
    }
    if data.get("scope") == "project":
        identity.update(scope="project", project_root=data["project_root"])
    return _digest(identity)


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
                or _sensitive_name(lower)
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
        option = re.fullmatch(r"--([A-Za-z0-9_-]+)=(.*)", value)
        if option and _sensitive_name(option.group(1)):
            if option.group(2) and not _ENV_PLACEHOLDER.fullmatch(option.group(2)):
                return {"blocked": "literal-secret"}, True
        parsed = urlsplit(value)
        if parsed.username or parsed.password:
            return {"blocked": "literal-secret"}, True
        for key, child in parse_qsl(parsed.query, keep_blank_values=True):
            if _sensitive_name(key) and child and not _ENV_PLACEHOLDER.fullmatch(child):
                return {"blocked": "literal-secret"}, True
        if secret_context and value and not _ENV_PLACEHOLDER.fullmatch(value):
            return {"blocked": "literal-secret"}, True
    return value, False


def _candidate(
    root: _Root,
    path: Path,
    kind: str,
    name: str,
    payload: Any | None = None,
    *,
    source_targets: list[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if error := path_boundary_error(root.path, path):
        raise ImportProtocolError(f"unsafe native source: {error}")
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
        "source_target": sorted(source_targets or [root.target]),
        "provenance": "local-only",
        "payload": clean_payload,
        "content_fingerprint": content,
        "source_preimage_ids": [preimage["id"]],
        "executable_paths": sorted(executables),
        "secret_blocked": blocked,
    }


def _unsupported_candidate(target: str, name: str, reason: str) -> dict[str, Any]:
    """Return one redacted, path-free blocker that can be left unmanaged."""
    identity = {"target": target, "name": name, "reason": reason}
    return {
        "id": _digest(identity)[:32],
        "kind": "unsupported",
        "name": name,
        "root_id": f"{target}-config",
        "source_handle": f"unsupported:{target}:{name}",
        "source_target": [target],
        "provenance": "native-unsupported",
        "payload": {
            "unsupported_reason": reason,
            "leave_unmanaged_available": True,
        },
        "content_fingerprint": _digest(identity),
        "source_preimage_ids": [],
        "executable_paths": [],
        "secret_blocked": False,
    }


def _root_path(target: str) -> Path:
    if target not in KNOWN_TARGETS:
        raise ImportProtocolError(f"unsupported source target: {target}")
    root = _user_target_root(target)
    if root is None:
        raise ImportProtocolError(f"source target is not available: {target}")
    return root


def _user_target_root(target: str) -> Path | None:
    try:
        profile = KNOWN_TARGETS[target].for_scope(user_scope=True)
    except OSError:
        return None
    if profile is None:
        return None
    if profile.resolved_deploy_root is not None:
        return profile.resolved_deploy_root.resolve(strict=False)
    root = Path(profile.root_dir).expanduser()
    return (root if root.is_absolute() else Path.home() / root).resolve(strict=False)


def _discover_unmanaged_clients(
    managed_targets: tuple[str, ...] | list[str] = (),
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    candidates: list[dict[str, Any]] = []
    preimages: list[dict[str, Any]] = []
    for target in _UNMANAGED_NATIVE_CLIENTS:
        if target in managed_targets:
            continue
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


def _resource_root(resource: NativeResource) -> _Root:
    target = resource.targets[0]
    shared_agents = (Path.home() / ".agents").resolve(strict=False)
    root_id = (
        "shared-agent-skills"
        if resource.root.resolve(strict=False) == shared_agents
        else f"{target}-config"
    )
    return _Root(root_id, target, resource.root)


def _discover_filesystem_targets(
    targets: tuple[str, ...] | list[str],
    *,
    discover_resources: Callable[..., list[NativeResource]] = discover_filesystem_resources,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    candidates: list[dict[str, Any]] = []
    preimages: list[dict[str, Any]] = []
    for resource in discover_resources(targets):
        if resource.blocked_reason:
            candidates.append(
                _unsupported_candidate(resource.targets[0], resource.name, resource.blocked_reason)
            )
            continue
        root = _resource_root(resource)
        hook = snapshot_hook(resource) if resource.kind == "hook" else None
        if hook is not None and hook.blocked_reason:
            candidates.append(
                _unsupported_candidate(resource.targets[0], resource.name, hook.blocked_reason)
            )
            continue
        payload: Any | None = None
        if resource.strategy == "compiled":
            compiled = adopt_compiled_instruction(resource)
            payload = {
                "import_layout": "compiled-instruction",
                "target": compiled.target,
                "format_id": compiled.format_id,
                "relative_path": compiled.relative_path.as_posix(),
            }
        elif hook is not None:
            payload = {
                "import_layout": "hook-bundle",
                "descriptor": hook.payload,
                "scripts": [
                    {
                        "preimage_id": _preimage(script.path)["id"],
                        "relative_path": script.path.relative_to(resource.root).as_posix(),
                    }
                    for script in hook.scripts
                ],
            }
        preimage, candidate = _candidate(
            root,
            resource.path,
            resource.kind,
            resource.name,
            payload,
            source_targets=list(resource.targets),
        )
        preimages.append(preimage)
        if hook is not None:
            script_preimages = [_preimage(script.path) for script in hook.scripts]
            candidate["source_preimage_ids"].extend(item["id"] for item in script_preimages)
            candidate["content_fingerprint"] = _digest(
                {
                    "descriptor": preimage["content_fingerprint"],
                    "scripts": [item["content_fingerprint"] for item in script_preimages],
                }
            )
            candidate["executable_paths"] = sorted(
                script.path.relative_to(resource.root).as_posix()
                for script in hook.scripts
                if stat.S_IMODE(script.path.stat().st_mode) & 0o111
            )
            for script_preimage in script_preimages:
                preimages.append(script_preimage)
        candidates.append(candidate)
    return candidates, preimages


def _discover_special_targets(
    targets: tuple[str, ...] | list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    selected = set(targets)
    resources: list[NativeResource] = []
    if "copilot-cowork" in selected:
        try:
            resources.extend(discover_cowork_resources())
        except OSError:
            resources.append(
                NativeResource(
                    Path.home(),
                    Path.home(),
                    "unsupported",
                    "copilot-cowork",
                    ("copilot-cowork",),
                    "custom",
                    "source-resolver-error",
                )
            )
    if "copilot" in selected:
        try:
            root = _user_target_root("copilot")
            if root is not None:
                resources.extend(discover_canvas_resources(root=root))
        except OSError:
            resources.append(
                NativeResource(
                    Path.home(),
                    Path.home(),
                    "unsupported",
                    "copilot",
                    ("copilot",),
                    "custom",
                    "source-resolver-error",
                )
            )

    candidates: list[dict[str, Any]] = []
    preimages: list[dict[str, Any]] = []
    for resource in resources:
        if resource.blocked_reason:
            candidates.append(
                _unsupported_candidate(resource.targets[0], resource.name, resource.blocked_reason)
            )
            continue
        root = _resource_root(resource)
        payload = {"import_layout": "canvas"} if resource.kind == "canvas" else None
        kind = "package" if resource.kind == "canvas" else resource.kind
        preimage, candidate = _candidate(
            root,
            resource.path,
            kind,
            resource.name,
            payload,
            source_targets=list(resource.targets),
        )
        if resource.kind == "canvas":
            candidate["content_fingerprint"] = preimage["content_fingerprint"]
        preimages.append(preimage)
        candidates.append(candidate)

    if "copilot-app" in selected:
        try:
            workflows = discover_copilot_app_workflows()
        except (OSError, ValueError):
            candidates.append(
                _unsupported_candidate("copilot-app", "copilot-app", "source-resolver-error")
            )
            workflows = []
        for workflow in workflows:
            if workflow.managed:
                continue
            root = _resource_root(workflow.native)
            preimage, candidate = _candidate(
                root,
                workflow.native.path,
                "command",
                workflow.native.name,
                {"import_layout": "workflow", "workflow": workflow.payload},
                source_targets=list(workflow.native.targets),
            )
            preimages.append(preimage)
            candidates.append(candidate)
    return candidates, preimages


def _discover_plugins(
    targets: tuple[str, ...] | list[str],
    *,
    discover_state: Callable[..., Any] = discover_plugin_state,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    roots = {
        target: root
        for target in sorted(set(targets))
        if (root := _user_target_root(target)) is not None
    }
    discovered = discover_state(roots)
    candidates: list[dict[str, Any]] = []
    preimages: list[dict[str, Any]] = []
    for plugin in discovered.plugins:
        if plugin.blocked_reason:
            candidates.append(
                _unsupported_candidate(plugin.targets[0], plugin.name, plugin.blocked_reason)
            )
            continue
        root = _Root(
            f"plugin-{_digest(str(plugin.path.resolve(strict=False)))[:16]}",
            plugin.targets[0],
            plugin.path if plugin.path.is_dir() else plugin.path.parent,
        )
        payload = {
            **plugin.payload,
            "activation_paths": [
                str(path.resolve(strict=False)) for path in plugin.activation_paths
            ],
        }
        preimage, candidate = _candidate(
            root,
            plugin.path,
            "plugin",
            plugin.name,
            payload,
            source_targets=list(plugin.targets),
        )
        candidate["provenance"] = plugin.provenance
        if plugin.path.is_dir() and plugin.payload.get("source") == "secured-path":
            candidate["content_fingerprint"] = preimage["content_fingerprint"]
        preimages.append(preimage)
        candidates.append(candidate)
    for marketplace in discovered.marketplaces:
        if marketplace.blocked_reason:
            candidates.append(
                _unsupported_candidate(
                    marketplace.target, marketplace.name, marketplace.blocked_reason
                )
            )
            continue
        root = _Root(f"{marketplace.target}-config", marketplace.target, marketplace.path.parent)
        preimage, candidate = _candidate(
            root,
            marketplace.path,
            "marketplace",
            marketplace.name,
            marketplace.payload,
            source_targets=[marketplace.target],
        )
        preimages.append(preimage)
        candidates.append(candidate)
    return candidates, preimages


def _discover_mcp_targets(
    targets: tuple[str, ...] | list[str],
    *,
    project_root: Path | None = None,
    discover_sources: Callable[..., Any] = discover_mcp_sources,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    candidates: list[dict[str, Any]] = []
    preimages: list[dict[str, Any]] = []
    for source in discover_sources(targets, project_root=project_root):
        expected_scope = "project" if project_root is not None else "global"
        if source.scope != expected_scope:
            raise ImportProtocolError("MCP discovery mixed global and project sources")
        if project_root is not None and source.project_root != project_root:
            raise ImportProtocolError("MCP discovery returned a mismatched project root")
        if source.blocked_reason:
            candidates.append(
                _unsupported_candidate(source.client, source.client, source.blocked_reason)
            )
            continue
        root = _Root(f"{source.client}-config", source.client, source.path.parent)
        for name, payload in sorted(source.servers.items()):
            preimage, candidate = _candidate(root, source.path, "mcp", str(name), payload)
            preimages.append(preimage)
            candidates.append(candidate)
    return candidates, preimages


def _discover_target_extras(target: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if target not in KNOWN_TARGETS:
        raise ImportProtocolError(f"unsupported source target: {target}")
    root_path = _user_target_root(target)
    if root_path is None:
        return [], []
    root = _Root(f"{target}-config", target, root_path)
    candidates: list[dict[str, Any]] = []
    preimages: list[dict[str, Any]] = []
    if target == "claude":
        claude_md = root_path / "CLAUDE.md"
        if claude_md.is_file():
            compiled = adopt_compiled_instruction(
                NativeResource(
                    root_path,
                    claude_md,
                    "instruction",
                    "compiled-claude-md",
                    ("claude",),
                    "compiled",
                )
            )
            preimage, candidate = _candidate(
                root,
                claude_md,
                "instruction",
                compiled.name,
                {
                    "import_layout": "compiled-instruction",
                    "target": compiled.target,
                    "format_id": compiled.format_id,
                    "relative_path": compiled.relative_path.as_posix(),
                },
            )
            preimages.append(preimage)
            candidates.append(candidate)
    # Preserve the pre-adapter Claude import source while native installs
    # converge on the adapter-owned ~/.claude.json path.
    legacy_settings = root_path / "settings.json"
    if target == "claude" and legacy_settings.is_file():
        try:
            data = _load_structured(legacy_settings) or {}
        except (OSError, ValueError, json.JSONDecodeError):
            candidates.append(
                _unsupported_candidate("claude", "claude", "malformed-or-unreadable-mcp-document")
            )
            return candidates, preimages
        for name, payload in sorted(data.get("mcpServers", {}).items()):
            preimage, candidate = _candidate(root, legacy_settings, "mcp", str(name), payload)
            preimages.append(preimage)
            candidates.append(candidate)
        if data.get("hooks"):
            native = NativeResource(
                root_path,
                legacy_settings,
                "hook",
                "settings-hooks",
                ("claude",),
                "snapshot",
            )
            hook = snapshot_hook(native)
            if hook is None:
                raise ImportProtocolError("legacy Claude hooks are malformed")
            script_preimages = [_preimage(script.path) for script in hook.scripts]
            preimage, candidate = _candidate(
                root,
                legacy_settings,
                "hook",
                "settings-hooks",
                {
                    "import_layout": "hook-bundle",
                    "descriptor": data["hooks"],
                    "scripts": [
                        {
                            "preimage_id": item["id"],
                            "relative_path": script.path.relative_to(root_path).as_posix(),
                        }
                        for script, item in zip(hook.scripts, script_preimages, strict=True)
                    ],
                },
            )
            candidate["source_preimage_ids"].extend(item["id"] for item in script_preimages)
            candidate["content_fingerprint"] = _digest(
                {
                    "descriptor": preimage["content_fingerprint"],
                    "scripts": [item["content_fingerprint"] for item in script_preimages],
                }
            )
            candidate["executable_paths"] = sorted(
                script.path.relative_to(root_path).as_posix()
                for script in hook.scripts
                if stat.S_IMODE(script.path.stat().st_mode) & 0o111
            )
            preimages.append(preimage)
            preimages.extend(script_preimages)
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
