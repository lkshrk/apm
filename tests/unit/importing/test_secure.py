from __future__ import annotations

import os
from pathlib import Path

import pytest

from apm_cli.importing.journal import journal_root
from apm_cli.importing.secure import (
    SecureRoot,
    _current_windows_user_sid,
    _read_windows_sddl,
    _verify_private_sddl,
    harden_path,
)


def test_private_sddl_rejects_any_extra_ace() -> None:
    user = "S-1-5-21-1000"
    _verify_private_sddl(f"O:SYG:SYD:P(A;;FA;;;{user})(A;;FA;;;SY)", user, is_dir=False)
    _verify_private_sddl(
        f"O:SYG:SYD:AIP(A;;FA;;;{user})(A;;FA;;;SY)",
        f" {user} ",
        is_dir=False,
    )
    with pytest.raises(PermissionError, match="mismatch"):
        _verify_private_sddl(
            f"O:SYG:SYD:P(A;;FA;;;{user})(A;;FA;;;SY)(A;;FR;;;WD)",
            user,
            is_dir=False,
        )
    with pytest.raises(PermissionError, match="mismatch"):
        _verify_private_sddl(f"O:SYG:SYD:P(A;;FR;;;{user})(A;;FA;;;SY)", user, is_dir=False)
    with pytest.raises(PermissionError, match=r"flags='AI'.*expected_user"):
        _verify_private_sddl(f"O:SYG:SYD:AI(A;;FA;;;{user})(A;;FA;;;SY)", user, is_dir=False)


def test_private_sddl_requires_exact_object_inheritance_flags() -> None:
    user = "S-1-5-21-1000"
    directory = f"D:P(A;OICI;FA;;;{user})(A;CIOI;FA;;;SY)"
    _verify_private_sddl(directory, user, is_dir=True)
    with pytest.raises(PermissionError, match="expected_ace_flags"):
        _verify_private_sddl(f"D:P(A;OI;FA;;;{user})(A;OICI;FA;;;SY)", user, is_dir=True)
    with pytest.raises(PermissionError, match="expected_ace_flags"):
        _verify_private_sddl(directory, user, is_dir=False)


def test_private_sddl_accepts_la_only_for_current_rid_500_account() -> None:
    administrator = "S-1-5-21-100-200-300-500"
    _verify_private_sddl("D:P(A;;FA;;;LA)(A;;FA;;;SY)", administrator, is_dir=False)
    with pytest.raises(PermissionError, match=r"principals=\['LA', 'SY'\]"):
        _verify_private_sddl(
            "D:P(A;;FA;;;LA)(A;;FA;;;SY)",
            "S-1-5-21-100-200-300-1001",
            is_dir=False,
        )
    for forbidden in ("BA", "OW"):
        with pytest.raises(PermissionError, match="mismatch"):
            _verify_private_sddl(
                f"D:P(A;;FA;;;{forbidden})(A;;FA;;;SY)",
                administrator,
                is_dir=False,
            )


def test_secure_root_rejects_parent_traversal(tmp_path: Path) -> None:
    root = SecureRoot(tmp_path / "root").ensure()

    with pytest.raises(ValueError, match="escapes secure root"):
        root.write_text("../outside", "secret")

    assert not (tmp_path / "outside").exists()


def test_secure_root_rejects_symlink_ancestor(tmp_path: Path) -> None:
    root = SecureRoot(tmp_path / "root").ensure()
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (root.path / "linked").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="escapes secure root"):
        root.write_text("linked/leak", "secret")

    assert not (outside / "leak").exists()


def test_secure_root_rejects_symlink_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        SecureRoot(linked_root).ensure()


def test_journal_root_rejects_operation_id_traversal(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    with pytest.raises(ValueError):
        journal_root("../escape", create=True)

    assert not (home / ".apm" / "escape").exists()


def test_journal_root_rejects_symlinked_journal_base(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    apm = home / ".apm"
    apm.mkdir(parents=True, mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (apm / "import-journal").symlink_to(outside, target_is_directory=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    with pytest.raises(ValueError, match="symlink"):
        journal_root("a" * 32, create=True)

    assert not (outside / ("a" * 32)).exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission contract")
def test_secure_root_enforces_private_modes_under_hostile_umask(tmp_path: Path) -> None:
    previous = os.umask(0)
    try:
        root = SecureRoot(tmp_path / "root").ensure()
        written = root.write_text("nested/secret", "secret")
    finally:
        os.umask(previous)

    assert root.path.stat().st_mode & 0o777 == 0o700
    assert written.parent.stat().st_mode & 0o777 == 0o700
    assert written.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name == "nt", reason="Unix dirfd contract")
def test_secure_write_does_not_follow_root_swapped_during_replace(monkeypatch, tmp_path):
    root = SecureRoot(tmp_path / "root").ensure()
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    original_replace = os.replace
    swapped = False

    def swap_then_replace(*args, **kwargs):
        nonlocal swapped
        if not swapped:
            swapped = True
            original_replace(root.path, tmp_path / "detached")
            root.path.symlink_to(outside, target_is_directory=True)
        return original_replace(*args, **kwargs)

    monkeypatch.setattr(os, "replace", swap_then_replace)
    with pytest.raises(ValueError, match="symlink"):
        root.write_text("secret", "value")
    assert not (outside / "secret").exists()
    assert (tmp_path / "detached" / "secret").read_text(encoding="utf-8") == "value"


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL runtime contract")
def test_windows_private_acl_runtime(tmp_path: Path) -> None:
    root = tmp_path / "private"
    root.mkdir()
    harden_path(root)
    user_sid = _current_windows_user_sid()
    _verify_private_sddl(_read_windows_sddl(root), user_sid, is_dir=True)
    leaf = root / "secret"
    leaf.write_text("secret", encoding="utf-8")
    harden_path(leaf)
    _verify_private_sddl(_read_windows_sddl(leaf), user_sid, is_dir=False)


@pytest.mark.skipif(os.name != "nt", reason="Windows nonexistent-leaf contract")
def test_windows_acl_hardening_rejects_nonexistent_leaf_before_acl_calls(
    tmp_path: Path,
) -> None:
    with pytest.raises(FileNotFoundError):
        harden_path(tmp_path / "missing")


@pytest.mark.skipif(os.name != "nt", reason="Windows exact DACL runtime contract")
def test_windows_private_acl_rejects_extra_ace(tmp_path: Path) -> None:
    import subprocess

    root = tmp_path / "private-extra"
    root.mkdir()
    harden_path(root)
    subprocess.run(
        ["icacls", str(root), "/grant", "*S-1-1-0:(OI)(CI)R"],
        check=True,
        capture_output=True,
        text=True,
    )
    user_sid = _current_windows_user_sid()
    with pytest.raises(PermissionError, match="mismatch"):
        _verify_private_sddl(_read_windows_sddl(root), user_sid, is_dir=True)
    harden_path(root)
    _verify_private_sddl(_read_windows_sddl(root), user_sid, is_dir=True)


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse runtime contract")
def test_windows_reparse_root_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink/reparse"):
        SecureRoot(linked).ensure()


@pytest.mark.skipif(os.name != "nt", reason="Windows component-handle runtime contract")
def test_windows_component_swap_is_rejected_before_write(monkeypatch, tmp_path: Path) -> None:
    import subprocess

    from apm_cli.importing import secure

    root = SecureRoot(tmp_path / "root").ensure()
    outside = tmp_path / "outside"
    outside.mkdir()
    detached = tmp_path / "detached"
    original_harden = secure.harden_path
    swapped = False

    def swap_after_parent_harden(path, **kwargs):
        nonlocal swapped
        original_harden(path, **kwargs)
        if not swapped and Path(path) == root.path:
            swapped = True
            os.replace(root.path, detached)
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(root.path), str(outside)],
                check=True,
                capture_output=True,
                text=True,
            )

    monkeypatch.setattr(secure, "harden_path", swap_after_parent_harden)
    with pytest.raises(ValueError, match=r"reparse|changed"):
        root.write_text("secret", "value")
    assert not (outside / "secret").exists()
