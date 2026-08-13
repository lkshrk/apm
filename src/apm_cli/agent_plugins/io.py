"""Bounded JSON loading helpers for Agent Plugins documents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 5 * 1024 * 1024


def read_json_document(path: Path) -> Any:
    """Read and decode a JSON file with a fixed size cap."""
    if path.is_symlink():
        raise ValueError(f"JSON file {path} must not be a symlink")
    if not path.is_file():
        raise ValueError(f"JSON file {path} must be a regular file")
    size = path.stat().st_size
    if size > MAX_JSON_BYTES:
        raise ValueError(f"JSON file {path} exceeds {MAX_JSON_BYTES}-byte cap ({size} bytes)")
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except (ValueError, RecursionError, MemoryError) as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
