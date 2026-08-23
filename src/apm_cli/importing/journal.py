"""Durable import journal and lifecycle fence."""

from __future__ import annotations

import contextlib
import contextvars
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .secure import SecureRoot

TERMINAL_STATES = frozenset({"complete", "rolled-back"})
_allowed_operation: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "apm_import_operation", default=None
)
_OPERATION_ID = re.compile(r"^[a-f0-9]{32}$")


def _validated_operation_id(operation_id: str) -> str:
    if not isinstance(operation_id, str) or not _OPERATION_ID.fullmatch(operation_id):
        raise ValueError("operation ID must be exactly 32 lowercase hexadecimal characters")
    return operation_id


def journal_base() -> Path:
    return Path.home() / ".apm" / "import-journal"


def journal_root(operation_id: str, *, create: bool = False) -> SecureRoot:
    operation_id = _validated_operation_id(operation_id)
    base = SecureRoot(journal_base())
    if create:
        base.ensure()
    elif base.path.exists():
        base.verify()
    root_path = base.contained(operation_id) if base.path.exists() else base.path / operation_id
    root = SecureRoot(root_path)
    return root.ensure() if create else root


def read_journal(operation_id: str) -> dict[str, Any] | None:
    operation_id = _validated_operation_id(operation_id)
    root = journal_root(operation_id)
    if not root.path.is_dir():
        return None
    root.verify()
    path = root.contained("journal.json")
    if not path.is_file() or path.is_symlink():
        return None
    root.verify(path)
    return json.loads(path.read_text(encoding="utf-8"))


def write_journal(data: dict[str, Any]) -> None:
    root = journal_root(str(data["operation_id"]), create=True)
    root.write_text("journal.json", json.dumps(data, indent=2, sort_keys=True) + "\n")


def unresolved_operation() -> dict[str, Any] | None:
    base = journal_base()
    if not base.is_dir():
        return None
    SecureRoot(base).verify()
    allowed = _allowed_operation.get()
    for path in sorted(base.iterdir()):
        if not path.is_dir() or path.is_symlink() or path.name == allowed:
            continue
        try:
            data = read_journal(path.name)
        except ValueError:
            continue
        if data and data.get("state") not in TERMINAL_STATES:
            return data
    return None


def assert_lifecycle_unfenced() -> None:
    data = unresolved_operation()
    if data is None:
        return
    operation = data["operation_id"]
    raise RuntimeError(
        f"APM import operation {operation} is unresolved; "
        f"run 'apm import status --operation {operation} --format json'"
    )


@contextlib.contextmanager
def allow_operation(operation_id: str) -> Iterator[None]:
    operation_id = _validated_operation_id(operation_id)
    token = _allowed_operation.set(operation_id)
    try:
        yield
    finally:
        _allowed_operation.reset(token)
