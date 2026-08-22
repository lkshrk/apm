"""Unit contracts for workspace lifecycle serialization."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from filelock import Timeout

from apm_cli.cli import cli
from apm_cli.install.locking import (
    LifecycleBusyError,
    acquire_lifecycle_lock,
    lifecycle_lock,
)

pytestmark = pytest.mark.windows_compat


def test_lifecycle_lock_is_reentrant_per_process() -> None:
    first = lifecycle_lock()
    second = lifecycle_lock()

    assert first is second
    with first, second:
        assert first.is_locked


def test_lifecycle_lock_uses_isolated_windows_home(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Global locking follows Path.home instead of the runner's real profile."""
    home = tmp_path / "windows-home"
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    lock = acquire_lifecycle_lock()
    try:
        assert Path(lock.lock_file) == (home / ".apm" / ".apm-lifecycle.lock").resolve()
    finally:
        lock.release()


def test_busy_error_names_lock_path_and_wait(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    lock = lifecycle_lock()

    with (
        patch.object(lock, "acquire", side_effect=Timeout(lock.lock_file)),
        pytest.raises(LifecycleBusyError, match=r"waited 0.25s.*\.apm-lifecycle\.lock"),
    ):
        acquire_lifecycle_lock(timeout=0.25)


def test_install_root_redirect_teardown_error_releases_lock(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "apm.yml").write_text("name: fixture\nversion: 1.0.0\n", encoding="ascii")
    redirect = MagicMock()
    redirect.__enter__.return_value = None
    redirect.__exit__.side_effect = RuntimeError("teardown failed")

    with patch("apm_cli.install.root_redirect.install_root_redirect", return_value=redirect):
        result = CliRunner().invoke(cli, ["install"])

    assert result.exit_code != 0
    assert not lifecycle_lock().is_locked


def test_uninstall_cleanup_error_releases_lock(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "apm.yml").write_text("name: fixture\nversion: 1.0.0\n", encoding="ascii")

    with patch(
        "apm_cli.commands.uninstall.cli._cleanup_staged_local_refreshes",
        side_effect=RuntimeError("cleanup failed"),
    ):
        result = CliRunner().invoke(cli, ["uninstall", "missing"])

    assert result.exit_code != 0
    assert not lifecycle_lock().is_locked
