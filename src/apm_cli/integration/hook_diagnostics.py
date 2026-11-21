"""Shared native hook event diagnostics."""

import logging

from apm_cli.utils.console import _rich_warning

_log = logging.getLogger(__name__)
# Expected hook event naming convention per target.
# Used to warn when a package author deploys events whose casing does not
# match the target's convention AND no explicit rename mapping exists.
_HOOK_EVENT_EXPECTED_CASING: dict[str, str] = {
    "copilot": "camelCase",
    "vscode": "PascalCase",
    "claude": "PascalCase",
    "cursor": "camelCase",
    "codex": "PascalCase",
    "gemini": "PascalCase",
    "antigravity": "PascalCase",
    "windsurf": "PascalCase",
    "kiro": "PascalCase",
}


def _detect_event_casing(name: str) -> str | None:
    """Return 'camelCase', 'PascalCase', or None for an event name string."""
    if not name or not name[0].isalpha():
        return None
    if name[0].islower() and any(c.isupper() for c in name[1:]):
        return "camelCase"
    if name[0].isupper():
        return "PascalCase"
    return None


def _sanitize_event_name(name: str) -> str:
    """Return event name with non-printable-ASCII characters stripped, for safe logging."""
    return "".join(c for c in name if 0x20 <= ord(c) <= 0x7E)


def _emit_hook_event_diagnostics(
    event_names: list[str],
    target_key: str,
    event_map: dict[str, str],
) -> None:
    """Log hook events per-target and warn on unmapped casing mismatches.

    This is informational only -- it never blocks deployment.
    """
    if not event_names:
        return
    event_label = "hook event" if len(event_names) == 1 else "hook events"
    _log.info(
        "target %s: detected %s: %s",
        target_key,
        event_label,
        ", ".join(sorted(_sanitize_event_name(n) for n in event_names)),
    )
    expected_casing = _HOOK_EVENT_EXPECTED_CASING.get(target_key)
    if not expected_casing:
        return
    # Warn for events whose detected casing does not match the target convention
    # and that are not covered by an explicit rename in event_map.
    mismatched = [
        n
        for n in event_names
        if _detect_event_casing(n) not in (None, expected_casing) and n not in event_map
    ]
    if mismatched:
        example = "preToolUse" if expected_casing == "camelCase" else "PreToolUse"
        safe_mismatched = sorted(_sanitize_event_name(n) for n in mismatched)
        _rich_warning(
            f"Hook events for target '{target_key}' may not be recognized: "
            f"{', '.join(safe_mismatched)}. "
            f"Target expects {expected_casing} (e.g. {example}). "
            f"Rename events to match the {expected_casing} convention, then reinstall."
        )
        _log.warning(
            "target %s: hook event casing mismatch (no mapping): %s",
            target_key,
            ", ".join(safe_mismatched),
        )
