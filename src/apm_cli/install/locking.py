"""Cross-process serialization for one mutable APM workspace."""

from __future__ import annotations

import contextlib
import os
import threading
import weakref
from collections.abc import Callable, Iterator
from functools import wraps
from pathlib import Path
from typing import Any, TypeVar

from filelock import FileLock, Timeout

LIFECYCLE_LOCK_TIMEOUT = 120.0
_LIFECYCLE_LOCK_NAME = ".apm-lifecycle.lock"

_locks: weakref.WeakValueDictionary[tuple[int, Path], FileLock] = weakref.WeakValueDictionary()
_locks_guard = threading.Lock()
_T = TypeVar("_T")


class LifecycleBusyError(RuntimeError):
    """Raised when another APM state mutation owns the lifecycle lock."""


def lifecycle_lock() -> FileLock:
    """Return the process-reentrant OS-user lifecycle lock."""
    lock_path = (Path.home() / ".apm" / _LIFECYCLE_LOCK_NAME).resolve()
    key = (os.getpid(), lock_path)
    with _locks_guard:
        lock = _locks.get(key)
        if lock is None:
            lock = FileLock(str(lock_path), timeout=LIFECYCLE_LOCK_TIMEOUT)
            _locks[key] = lock
        return lock


def acquire_lifecycle_lock(*, timeout: float = LIFECYCLE_LOCK_TIMEOUT) -> FileLock:
    """Acquire the lifecycle lock or raise a clear busy-workspace error."""
    lock = lifecycle_lock()
    Path(lock.lock_file).parent.mkdir(parents=True, exist_ok=True)
    try:
        lock.acquire(timeout=timeout)
    except Timeout as exc:
        raise LifecycleBusyError(
            f"APM state is busy: waited {timeout:g}s for lifecycle lock {lock.lock_file}"
        ) from exc
    return lock


@contextlib.contextmanager
def lifecycle_operation() -> Iterator[None]:
    """Serialize one complete APM state mutation."""
    lock = acquire_lifecycle_lock()
    try:
        from apm_cli.importing.journal import assert_lifecycle_unfenced

        assert_lifecycle_unfenced()
        yield
    finally:
        lock.release()


def serialized_lifecycle(run: Callable[..., _T]) -> Callable[..., _T]:
    """Serialize a command callback before its first state read."""

    @wraps(run)
    def wrapped(*args: Any, **kwargs: Any) -> _T:
        with lifecycle_operation():
            return run(*args, **kwargs)

    return wrapped
