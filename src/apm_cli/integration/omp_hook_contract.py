"""Fail-closed omp edge adapter for the canonical portable hook contract."""

from __future__ import annotations

import math
import os
import re
import shlex
from pathlib import Path

from apm_cli.hook_contract import HookContractError, _entries_to_ir, _thaw, parse_hook_source
from apm_cli.integration.hook_command_paths import (
    iter_plugin_root_paths,
    iter_relative_script_paths,
    plugin_root_relative_path,
)
from apm_cli.integration.hook_source_selection import _resolve_relative_hook_script
from apm_cli.utils.path_security import ensure_path_within, has_symlink_component

OMP_HOOK_EVENTS = frozenset(
    {
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "Stop",
        "SessionStart",
        "SessionEnd",
        "PreCompact",
        "PostCompact",
    }
)
OMP_TOOL_EVENTS = frozenset({"PreToolUse", "PostToolUse", "PostToolUseFailure"})
OMP_EVENT_ALIASES = {
    **{event[0].lower() + event[1:]: event for event in OMP_HOOK_EVENTS},
    "AgentStop": "Stop",
    "agentStop": "Stop",
}


def omp_package_files(package_root: Path) -> frozenset[Path]:
    """Inventory the complete runtime context, refusing unsafe filesystem nodes."""
    from apm_cli.install.cache_pin import MARKER_FILENAME

    root = Path(package_root).absolute()
    if root.is_symlink() or not root.is_dir():
        raise HookContractError(f"omp hook package root must be a regular directory: {root}")
    files: set[Path] = set()
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != ".git")
        for name in (*dirs, *names):
            path = Path(directory) / name
            if path.is_symlink():
                raise HookContractError(f"omp hook package context contains a symlink: {path}")
            if not path.is_dir() and not path.is_file():
                raise HookContractError(f"omp hook package context contains a special file: {path}")
        files.update(
            Path(directory) / name
            for name in names
            if Path(directory) != root or name != MARKER_FILENAME
        )
    return frozenset(files)


def _matcher(value: object, event: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise HookContractError("omp hook matcher must be a string")
    if event not in OMP_TOOL_EVENTS:
        raise HookContractError(f"omp cannot preserve {event} matcher semantics")
    if value in {"", "*"}:
        return value
    if re.search(r"mcp__.*__", value):
        raise HookContractError(
            "omp cannot translate Claude server-qualified MCP matchers; use native tool names"
        )
    # Validate a shared Python/ECMAScript subset without executing a JS runtime.
    if re.search(r"\(\?(?![:=!]|<[=!])|\\[AZ]|(?:\*|\+|\?|\})\+", value):
        raise HookContractError("omp matcher uses unsupported regular-expression syntax")
    try:
        re.compile(value)
    except re.error as exc:
        raise HookContractError(f"invalid omp hook matcher: {exc}") from exc
    return value


def _command(command: str, package_root: Path, source_dir: Path) -> str:
    """Keep plugin-root expansion at runtime; anchor literal relative scripts."""
    for match in iter_plugin_root_paths(command):
        path = package_root / plugin_root_relative_path(match.group(1))
        ensure_path_within(path, package_root)
        if has_symlink_component(package_root, path) or not (path.is_file() or path.is_dir()):
            raise HookContractError(
                f"omp hook references missing or unsafe package resource: {path}"
            )
    replacements: list[tuple[int, int, str]] = []
    for match in iter_relative_script_paths(command):
        path = _resolve_relative_hook_script(package_root, source_dir, match.group(1)[2:])
        if path is None or has_symlink_component(package_root, path) or not path.is_file():
            raise HookContractError(
                f"omp hook references missing relative script: {match.group(1)}"
            )
        start, end = match.span(1)
        quoted = (
            start > 0
            and end < len(command)
            and command[start - 1] in "\"'"
            and command[end] == command[start - 1]
        )
        if quoted:
            start -= 1
            end += 1
        replacements.append((start, end, shlex.quote(str(path.resolve()))))
    for start, end, replacement in reversed(replacements):
        command = command[:start] + replacement + command[end:]
    return command


def render_omp_hooks(
    data: dict, *, package_root: Path, source_dir: Path, owner: str, data_dir: Path
) -> dict:
    """Render validated HookIR, preserving explicit per-handler runtime context."""
    parse_hook_source(data)
    if os.name == "nt":
        raise HookContractError("omp command hooks require POSIX process-group cancellation")
    events = data.get("hooks", data)
    if "hooks" in data and set(data) - {"hooks", "version", "description"}:
        raise HookContractError("unsupported omp hook document fields")
    if "version" in data and (type(data["version"]) is not int or data["version"] != 1):
        raise HookContractError("omp hook source requires version 1 when specified")
    if "description" in data and not isinstance(data["description"], str):
        raise HookContractError("omp hook description must be a string")
    rendered: dict[str, list] = {}
    for raw_event, entries in events.items():
        event = OMP_EVENT_ALIASES.get(raw_event, raw_event)
        if event not in OMP_HOOK_EVENTS:
            raise HookContractError(f"omp has no equivalent for hook event {raw_event!r}")
        for binding in _entries_to_ir(entries, event).bindings:
            if binding.metadata or binding.provenance:
                raise HookContractError("unsupported omp hook binding metadata")
            matcher = _matcher(binding.matcher, event)
            handlers = []
            for handler in binding.handlers:
                options = _thaw(handler.metadata)
                if options.keys() - {"type", "shell", "env", "statusMessage"}:
                    raise HookContractError(
                        f"unsupported omp hook handler fields: {sorted(options.keys() - {'type', 'shell', 'env', 'statusMessage'})}"
                    )
                if "statusMessage" in options and not isinstance(options["statusMessage"], str):
                    raise HookContractError("omp hook statusMessage must be a string")
                if options.get("type", "command") != "command":
                    raise HookContractError("omp supports only synchronous command hook handlers")
                if handler.platform not in {"all", "posix"} or handler.provenance:
                    raise HookContractError("unsupported omp hook platform or source metadata")
                if handler.platform == "posix":
                    options.setdefault("shell", "bash")
                if (
                    not isinstance(handler.command, str)
                    or not handler.command.strip()
                    or "\0" in handler.command
                ):
                    raise HookContractError("omp command hook requires a nonempty NUL-free command")
                timeout = handler.timeout_seconds
                maximum = 1.5 if event == "SessionEnd" else 29
                if timeout is not None and (
                    type(timeout) not in (int, float)
                    or not math.isfinite(timeout)
                    or not 0 < timeout <= maximum
                ):
                    raise HookContractError(
                        f"omp {event} timeout must be positive and at most {maximum} seconds"
                    )
                shell = options.get("shell")
                if "shell" in options and (
                    not isinstance(shell, str) or not shell.strip() or "\0" in shell
                ):
                    raise HookContractError("omp shell must name a single executable")
                env = options.get("env")
                if "env" in options and (
                    not isinstance(env, dict)
                    or any(
                        not isinstance(key, str)
                        or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
                        or not isinstance(value, str)
                        or "\0" in value
                        for key, value in env.items()
                    )
                ):
                    raise HookContractError("omp hook env must map environment names to strings")
                result = {
                    **options,
                    "type": "command",
                    "command": _command(handler.command, package_root, source_dir),
                    "apm": {
                        "owner": owner,
                        "root": str(package_root.resolve()),
                        "dataDir": str(data_dir.resolve()),
                    },
                }
                if timeout is not None:
                    result["timeout"] = timeout
                handlers.append(result)
            if not handlers:
                raise HookContractError("omp hook binding requires a command handler")
            entry = {"hooks": handlers}
            if matcher is not None:
                entry["matcher"] = matcher
            rendered.setdefault(event, []).append(entry)
    return {"hooks": rendered}
