"""Read-only checks against omp's native extension-module name namespace."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path

from apm_cli.adapters.client.omp import OmpClientAdapter
from apm_cli.hook_contract import HookContractError
from apm_cli.integration.extension_discovery import native_extension_name


def _json_object(path: Path) -> dict:
    """Mirror native JSON discovery without executing modules or changing settings."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (ValueError, UnicodeError):
        # The native loader ignores malformed manifests/settings too.
        return {}
    except OSError as exc:
        raise HookContractError(f"cannot inspect omp extension namespace: {path}") from exc
    return value if isinstance(value, dict) else {}


def _declared_entry(root: Path, value: str) -> Path | None:
    path = Path(os.path.abspath(root / value))
    if path.is_dir():
        path = next(
            (path / name for name in ("index.ts", "index.js") if (path / name).is_file()), path
        )
    return path if path.is_file() else None


def native_extension_module_paths(directory: Path) -> Iterator[Path]:
    """Enumerate the native one-level module rules, including linked entries."""
    if not directory.is_dir():
        return
    try:
        children = sorted(directory.iterdir())
    except OSError as exc:
        raise HookContractError(f"cannot inspect omp extension namespace: {directory}") from exc
    for child in children:
        if child.name.startswith("."):
            continue
        if child.is_file() and child.suffix in {".ts", ".js"}:
            yield child.absolute()
            continue
        if not child.is_dir():
            continue
        package = _json_object(child / "package.json")
        native = package.get("omp")
        if native is None:
            native = package.get("pi")
        declarations = native.get("extensions") if isinstance(native, dict) else None
        entries = (
            [value for value in declarations if isinstance(value, str)]
            if isinstance(declarations, list)
            else []
        )
        if entries:
            for value in entries:
                resolved = _declared_entry(child, value)
                if resolved is not None:
                    yield resolved
        else:
            for name in ("index.ts", "index.js"):
                candidate = child / name
                if candidate.is_file():
                    yield candidate.absolute()
                    break


def _settings_modules(target_root: Path, cwd: Path) -> Iterator[Path]:
    values = _json_object(target_root / "settings.json").get("extensions")
    if not isinstance(values, list):
        return
    for value in values:
        if not isinstance(value, str):
            continue
        expanded = Path(value).expanduser()
        path = Path(os.path.abspath(expanded if expanded.is_absolute() else cwd / expanded))
        if path.is_dir():
            yield from native_extension_module_paths(path)
        elif path.is_file():
            yield path


def preflight_omp_hook_namespace(
    target_root: Path,
    project_root: Path,
    *,
    user_scope: bool,
    bridge_paths: Mapping[str, str],
    verify_owned_bridge: Callable[[Path, str], None],
) -> None:
    """Reject foreign names and ambiguous ancestor bridges before any writes.

    Native capability discovery names entries before its path deduplication, so
    different directories can shadow one another. Fixed scope names preserve
    portable replay while keeping the user and project bridges independent.
    """
    scope = "user" if user_scope else "project"
    cwd = Path.cwd().absolute() if user_scope else project_root.absolute()
    user_root = (
        target_root
        if user_scope
        else OmpClientAdapter.config_path_for(project_root, True).parent.absolute()
    )
    roots: dict[Path, str] = {}

    def add_root(root: Path, root_scope: str) -> None:
        root = root.absolute()
        if root in roots and roots[root] != root_scope:
            raise HookContractError(
                "omp project and user hooks require distinct configuration roots"
            )
        roots[root] = root_scope

    add_root(target_root, scope)
    add_root(user_root, "user")
    temporary_root = Path(tempfile.gettempdir()).absolute()
    ceilings = {Path.home().absolute(), temporary_root}
    if os.name != "nt":
        # These are read-only traversal ceilings, not created temporary paths.
        # Keep shared POSIX ancestors bounded even with a private TMPDIR.
        filesystem_root = Path(os.path.sep)
        ceilings.update((filesystem_root / "tmp", filesystem_root / "var" / "tmp"))
    current = cwd
    while current not in ceilings and current.parent != current:
        add_root(current / ".omp", "project")
        current = current.parent

    reserved_names = {native_extension_name(Path(path)) for path in bridge_paths.values()}
    desired = (target_root / bridge_paths[scope]).absolute()
    seen = {native_extension_name(desired): desired}
    for root, root_scope in roots.items():
        expected = (root / bridge_paths[root_scope]).absolute()
        modules = (
            *native_extension_module_paths(root / "extensions"),
            *_settings_modules(root, cwd),
        )
        for module in modules:
            name = native_extension_name(module)
            if name not in reserved_names:
                continue
            if module != expected:
                raise HookContractError(
                    f"omp hook runtime name {name!r} collides with native extension {module}"
                )
            previous = seen.get(name)
            if previous is not None and previous != module:
                raise HookContractError(
                    f"ambiguous omp ancestor hook runtime name {name!r}: {previous} and {module}; "
                    "use one project hook scope"
                )
            verify_owned_bridge(root, root_scope)
            seen[name] = module
