"""Read-only discovery of native plugin and marketplace state."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from apm_cli.deps.plugin_parser import inspect_plugin_package
from apm_cli.importing.secure import SecureRoot, restore_file_bytes

_MAX_STATE_BYTES = 4 * 1024 * 1024
_MANIFESTS = (".claude-plugin/plugin.json", ".codex-plugin/plugin.json")
_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "credential",
        "credentials",
        "key",
        "password",
        "secret",
        "token",
    }
)


@dataclass(frozen=True)
class ActivationState:
    path: Path
    data: bytes
    mode: int


@dataclass(frozen=True)
class PluginImport:
    name: str
    path: Path
    targets: tuple[str, ...]
    provenance: str
    payload: dict[str, Any]
    activation_paths: tuple[Path, ...] = ()
    blocked_reason: str | None = None


@dataclass(frozen=True)
class MarketplaceImport:
    name: str
    path: Path
    target: str
    payload: dict[str, Any]
    blocked_reason: str | None = None


@dataclass(frozen=True)
class PluginDiscovery:
    plugins: tuple[PluginImport, ...]
    marketplaces: tuple[MarketplaceImport, ...]


def capture_activation(path: Path) -> ActivationState:
    """Capture exact activation bytes and mode for transactional restoration."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("plugin activation path is missing or is a symlink")
    if path.stat().st_size > _MAX_STATE_BYTES:
        raise ValueError("plugin activation file exceeds size limit")
    return ActivationState(path.resolve(), path.read_bytes(), stat.S_IMODE(path.stat().st_mode))


def restore_activation(state: ActivationState) -> None:
    """Restore an activation file byte-for-byte through the secure writer."""
    restore_file_bytes(state.path, state.data, state.mode)


def _read_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ValueError("state path is missing or is a symlink")
    if path.stat().st_size > _MAX_STATE_BYTES:
        raise ValueError("state file exceeds size limit")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError, MemoryError) as exc:
        raise ValueError("state file is malformed") from exc


def _present(path: Path) -> bool:
    try:
        path.lstat()
    except OSError:
        return False
    return True


def _plugin_state_dir(root: Path) -> Path | None:
    plugin_dir = Path(os.path.abspath(root.expanduser() / "plugins"))
    if not _present(plugin_dir):
        return None
    root_path = Path(os.path.abspath(root.expanduser()))
    root_resolved = root_path.resolve(strict=True)
    SecureRoot._reject_link_components(
        plugin_dir, message="plugin state contains a symlink/reparse component"
    )
    resolved = plugin_dir.resolve(strict=True)
    if not resolved.is_relative_to(root_resolved) or not plugin_dir.is_dir():
        raise ValueError("plugin state directory escapes target root")
    return plugin_dir


def _registry_file(plugin_dir: Path, filename: str) -> Path | None:
    path = plugin_dir / filename
    if not _present(path):
        return None
    SecureRoot._reject_link_components(
        path, message="plugin registry contains a symlink/reparse component"
    )
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(plugin_dir.resolve(strict=True)) or not path.is_file():
        raise ValueError("plugin registry escapes plugin state directory")
    return path


def _physical_key(path: Path) -> tuple[object, ...]:
    info = path.stat()
    if info.st_ino:
        return (info.st_dev, info.st_ino)
    return (os.path.normcase(str(path.resolve())),)


def _safe_relative_path(value: object, *, default: str) -> str:
    if value in (None, ""):
        return default
    if not isinstance(value, str):
        raise ValueError("marketplace path must be a string")
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("marketplace path escapes its repository")
    return path.as_posix()


def _sensitive_key(value: object) -> bool:
    return isinstance(value, str) and value.lower().replace("-", "_") in _SENSITIVE_KEYS


def _contains_sensitive_key(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            _sensitive_key(key) or _contains_sensitive_key(child) for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_sensitive_key(child) for child in value)
    return False


def _credential_bearing_url(value: str) -> bool:
    parsed = urlsplit(value)
    if parsed.password or (parsed.scheme in {"http", "https"} and parsed.username):
        return True
    for encoded in (parsed.query, parsed.fragment):
        if any(_sensitive_key(key) for key, _ in parse_qsl(encoded, keep_blank_values=True)):
            return True
    return False


def _marketplace_payload(raw: object) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("marketplace entry must be an object")
    if _contains_sensitive_key(raw):
        raise ValueError("marketplace entry contains credentials")
    source = raw.get("source", raw)
    if isinstance(source, str):
        source = {"url": source}
    if not isinstance(source, dict):
        raise ValueError("marketplace source must be an object")
    repo = source.get("repo") or source.get("repository")
    url = source.get("url")
    if not url and isinstance(repo, str) and repo.count("/") == 1:
        url = f"https://github.com/{repo}"
    if not isinstance(url, str) or not url.strip():
        raise ValueError("marketplace source has no canonical repository")
    if _credential_bearing_url(url):
        raise ValueError("marketplace source URL contains credentials")
    normalized: dict[str, Any] = {
        "url": url.strip(),
        "path": _safe_relative_path(
            source.get("path", raw.get("path")), default="marketplace.json"
        ),
    }
    if isinstance(repo, str) and repo:
        normalized["repo"] = repo
    ref = source.get("ref") or raw.get("ref") or raw.get("version")
    if isinstance(ref, str) and ref:
        normalized["ref"] = ref
    install_path = raw.get("installLocation") or raw.get("installPath")
    if isinstance(install_path, str) and install_path:
        normalized["install_path"] = str(Path(install_path).expanduser().resolve(strict=False))
    return {"source": normalized}


def _git_provenance(path: Path) -> dict[str, Any] | None:
    def git(*args: str) -> str:
        return subprocess.run(
            [
                "git",
                "-c",
                "safe.directory=*",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(path),
                *args,
            ],
            check=True,
            capture_output=True,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
            text=True,
            timeout=5,
        ).stdout.strip()

    try:
        root = Path(git("rev-parse", "--show-toplevel")).resolve(strict=True)
        revision = git("rev-parse", "HEAD")
        remote = git("remote", "get-url", "origin")
        dirty = git("status", "--porcelain", "--untracked-files=all")
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if dirty or len(revision) != 40 or any(c not in "0123456789abcdefABCDEF" for c in revision):
        return None
    if _credential_bearing_url(remote):
        return None
    payload: dict[str, Any] = {"source": remote, "ref": revision.lower()}
    relative = path.resolve().relative_to(root).as_posix()
    if relative != ".":
        payload["path"] = relative
    return payload


def _blocker(
    name: str, path: Path, target: str, reason: str, *, activation: bool = True
) -> PluginImport:
    return PluginImport(
        name=name,
        path=path,
        targets=(target,),
        provenance="local-only",
        payload={"unsupported_reason": reason},
        activation_paths=(path,) if activation else (),
        blocked_reason=reason,
    )


def discover_plugin_state(target_roots: Mapping[str, Path]) -> PluginDiscovery:
    """Discover plugins once per physical path across native target roots."""
    plugins: dict[tuple[object, ...], PluginImport] = {}
    blockers: list[PluginImport] = []
    marketplaces: list[MarketplaceImport] = []

    for target, root in sorted(target_roots.items()):
        lexical_plugin_dir = root / "plugins"
        installed_path = lexical_plugin_dir / "installed_plugins.json"
        marketplace_path = lexical_plugin_dir / "known_marketplaces.json"
        known: dict[str, dict[str, Any]] = {}

        try:
            plugin_dir = _plugin_state_dir(root)
        except (OSError, ValueError):
            safe_root = Path(os.path.abspath(root.expanduser()))
            blockers.append(
                _blocker(
                    "native-plugin-activation",
                    safe_root,
                    target,
                    "plugin-state-path-unsafe",
                    activation=False,
                )
            )
            marketplaces.append(
                MarketplaceImport(
                    "native-marketplaces",
                    safe_root,
                    target,
                    {"unsupported_reason": "plugin-state-path-unsafe"},
                    "plugin-state-path-unsafe",
                )
            )
            continue
        if plugin_dir is None:
            continue

        try:
            marketplace_path = _registry_file(plugin_dir, "known_marketplaces.json")
        except (OSError, ValueError):
            marketplaces.append(
                MarketplaceImport(
                    "native-marketplaces",
                    Path(os.path.abspath(root.expanduser())),
                    target,
                    {"unsupported_reason": "marketplace-registry-path-unsafe"},
                    "marketplace-registry-path-unsafe",
                )
            )
            marketplace_path = None

        if marketplace_path is not None:
            try:
                raw_marketplaces = _read_json(marketplace_path)
                entries = raw_marketplaces.get("marketplaces", raw_marketplaces)
                if isinstance(entries, list):
                    entries = {
                        str(entry.get("name", f"marketplace-{index}")): entry
                        for index, entry in enumerate(entries)
                        if isinstance(entry, dict)
                    }
                if not isinstance(entries, dict):
                    raise ValueError("marketplace registry must be an object or list")
                for name, raw in sorted(entries.items()):
                    try:
                        payload = _marketplace_payload(raw)
                        known[str(name)] = payload
                        marketplaces.append(
                            MarketplaceImport(str(name), marketplace_path, target, payload)
                        )
                    except ValueError:
                        marketplaces.append(
                            MarketplaceImport(
                                str(name),
                                marketplace_path,
                                target,
                                {"unsupported_reason": "marketplace-provenance-malformed"},
                                "marketplace-provenance-malformed",
                            )
                        )
            except ValueError:
                marketplaces.append(
                    MarketplaceImport(
                        "native-marketplaces",
                        marketplace_path,
                        target,
                        {"unsupported_reason": "marketplace-registry-malformed"},
                        "marketplace-registry-malformed",
                    )
                )

        activated: set[Path] = set()
        try:
            installed_path = _registry_file(plugin_dir, "installed_plugins.json")
        except (OSError, ValueError):
            blockers.append(
                _blocker(
                    "native-plugin-activation",
                    Path(os.path.abspath(root.expanduser())),
                    target,
                    "plugin-activation-path-unsafe",
                    activation=False,
                )
            )
            installed_path = None
        if installed_path is not None:
            try:
                installed = _read_json(installed_path)
                entries = (
                    installed.get("plugins", installed) if isinstance(installed, dict) else None
                )
                if not isinstance(entries, dict):
                    raise ValueError("plugin activation registry must be an object")
            except ValueError:
                blockers.append(
                    _blocker(
                        "native-plugin-activation",
                        installed_path,
                        target,
                        "plugin-activation-malformed",
                    )
                )
                entries = {}
            for reference, raw_records in sorted(entries.items()):
                records = raw_records if isinstance(raw_records, list) else [raw_records]
                for record in records:
                    if not isinstance(record, dict) or not isinstance(
                        record.get("installPath"), str
                    ):
                        blockers.append(
                            _blocker(
                                str(reference),
                                installed_path,
                                target,
                                "plugin-install-path-missing",
                            )
                        )
                        continue
                    unresolved = Path(record["installPath"]).expanduser()
                    try:
                        plugin_path = unresolved.resolve(strict=True)
                    except (OSError, RuntimeError):
                        blockers.append(
                            _blocker(
                                str(reference),
                                installed_path,
                                target,
                                "plugin-install-path-missing",
                            )
                        )
                        continue
                    try:
                        _, manifest = inspect_plugin_package(plugin_path)
                    except (OSError, ValueError, RuntimeError):
                        blockers.append(
                            _blocker(
                                str(reference), installed_path, target, "plugin-manifest-malformed"
                            )
                        )
                        continue
                    activated.add(plugin_path)
                    name = str(
                        manifest.get("name") or str(reference).split("@", 1)[0] or plugin_path.name
                    )
                    payload: dict[str, Any] = {"source": "secured-path"}
                    provenance = "local-only"
                    if "@" in str(reference):
                        plugin_name, marketplace_name = str(reference).rsplit("@", 1)
                        if marketplace_name in known:
                            provenance = "marketplace"
                            payload = {"plugin": plugin_name, "marketplace": marketplace_name}
                            version = record.get("version")
                            ref = (
                                record.get("gitCommitSha")
                                or record.get("commitSha")
                                or record.get("ref")
                            )
                            if isinstance(version, str) and version:
                                payload["version"] = version
                            if isinstance(ref, str) and ref:
                                payload["ref"] = ref
                    if provenance == "local-only" and (git_payload := _git_provenance(plugin_path)):
                        provenance, payload = "git", git_payload

                    key = _physical_key(plugin_path)
                    current = plugins.get(key)
                    if current is None:
                        plugins[key] = PluginImport(
                            name,
                            plugin_path,
                            (target,),
                            provenance,
                            payload,
                            (installed_path,),
                        )
                    elif (current.name, current.provenance, current.payload) != (
                        name,
                        provenance,
                        payload,
                    ):
                        plugins[key] = PluginImport(
                            current.name,
                            current.path,
                            tuple(sorted(set(current.targets) | {target})),
                            "local-only",
                            {"unsupported_reason": "plugin-activation-ambiguous"},
                            tuple(sorted(set(current.activation_paths) | {installed_path})),
                            "plugin-activation-ambiguous",
                        )
                    else:
                        plugins[key] = PluginImport(
                            current.name,
                            current.path,
                            tuple(sorted(set(current.targets) | {target})),
                            current.provenance,
                            current.payload,
                            tuple(sorted(set(current.activation_paths) | {installed_path})),
                        )

        if plugin_dir.is_dir():
            for marker in _MANIFESTS:
                for manifest_path in sorted(plugin_dir.glob(f"**/{marker}")):
                    plugin_path = manifest_path.parent.parent.resolve()
                    if plugin_path in activated:
                        continue
                    try:
                        _, manifest = inspect_plugin_package(plugin_path)
                    except (OSError, ValueError, RuntimeError):
                        blockers.append(
                            _blocker(
                                plugin_path.name, manifest_path, target, "plugin-manifest-malformed"
                            )
                        )
                        continue
                    key = _physical_key(plugin_path)
                    current = plugins.get(key)
                    targets = tuple(sorted(set(current.targets if current else ()) | {target}))
                    payload = _git_provenance(plugin_path) or {"source": "secured-path"}
                    provenance = "git" if payload.get("source") != "secured-path" else "local-only"
                    plugins[key] = PluginImport(
                        str(manifest.get("name") or plugin_path.name),
                        plugin_path,
                        targets,
                        provenance,
                        payload,
                        current.activation_paths if current else (),
                    )

    ordered_plugins = sorted(
        [*plugins.values(), *blockers],
        key=lambda item: (item.name, str(item.path), item.targets),
    )
    return PluginDiscovery(
        tuple(ordered_plugins),
        tuple(sorted(marketplaces, key=lambda item: (item.name, item.target))),
    )
