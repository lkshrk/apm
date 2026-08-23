"""Small operation-scoped secure filesystem boundary."""

from __future__ import annotations

import contextlib
import os
import re
import secrets
import shutil
import stat
from pathlib import Path

from apm_cli.utils.atomic_io import atomic_write_bytes, atomic_write_text, normalize_crlf_to_lf


def _ace_flags(value: str) -> list[str] | None:
    known = {"CI", "OI", "NP", "IO", "ID", "SA", "FA"}
    if len(value) % 2:
        return None
    tokens = [value[index : index + 2].upper() for index in range(0, len(value), 2)]
    return tokens if all(token in known for token in tokens) else None


def _verify_private_sddl(sddl: str, user_sid: str, *, is_dir: bool) -> None:
    if "D:" not in sddl:
        raise PermissionError(f"Windows ACL has no DACL: sddl={sddl!r}")
    dacl = sddl.split("D:", 1)[1].split("S:", 1)[0]
    flags, separator, ace_body = dacl.partition("(")
    aces = re.findall(r"\(([^)]*)\)", f"({ace_body}" if separator else "")
    parsed = [ace.split(";") for ace in aces]
    parsed_flags = [_ace_flags(ace[1].strip()) if len(ace) >= 2 else None for ace in parsed]
    expected_flags = ["CI", "OI"] if is_dir else []
    expected_sid = user_sid.strip().upper()
    expected_is_local_admin = (
        expected_sid.startswith("S-") and expected_sid.rsplit("-", 1)[-1] == "500"
    )
    principals = {
        (
            "SY"
            if ace[5].strip().upper() in {"SY", "S-1-5-18"}
            else expected_sid
            if ace[5].strip().upper() == "LA" and expected_is_local_admin
            else ace[5].strip().upper()
        )
        for ace in parsed
        if len(ace) >= 6
    }
    if (
        "P" not in flags
        or len(parsed) != 2
        or any(
            len(ace) < 6 or ace[0].strip().upper() != "A" or ace[2].strip().upper() != "FA"
            for ace in parsed
        )
        or any(flags is None or sorted(flags) != expected_flags for flags in parsed_flags)
        or principals != {expected_sid, "SY"}
    ):
        raise PermissionError(
            "private Windows ACL mismatch: "
            f"flags={flags!r} aces={aces!r} ace_flags={parsed_flags!r} "
            f"expected_ace_flags={expected_flags!r} principals={sorted(principals)!r} "
            f"expected_user={expected_sid!r} sddl={sddl!r}"
        )


def _read_windows_sddl(path: Path) -> str:
    """Read a file DACL through Win32 without PowerShell/module dependencies."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    get_named_security_info = advapi32.GetNamedSecurityInfoW
    get_named_security_info.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    get_named_security_info.restype = wintypes.DWORD
    convert_sddl = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
    convert_sddl.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.ULONG),
    ]
    convert_sddl.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [wintypes.HLOCAL]
    local_free.restype = wintypes.HLOCAL

    security_descriptor = wintypes.LPVOID()
    status = get_named_security_info(
        str(path),
        1,  # SE_FILE_OBJECT
        0x4,  # DACL_SECURITY_INFORMATION
        None,
        None,
        None,
        None,
        ctypes.byref(security_descriptor),
    )
    if status:
        raise OSError(status, f"cannot read Windows DACL for {path}")
    sddl = wintypes.LPWSTR()
    try:
        if not convert_sddl(
            security_descriptor,
            1,
            0x4,
            ctypes.byref(sddl),
            None,
        ):
            raise OSError(ctypes.get_last_error(), f"cannot encode Windows DACL for {path}")
        return sddl.value
    finally:
        if sddl:
            local_free(ctypes.cast(sddl, wintypes.HLOCAL))
        if security_descriptor:
            local_free(ctypes.cast(security_descriptor, wintypes.HLOCAL))


def _current_windows_user_sid() -> str:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [("sid", wintypes.LPVOID), ("attributes", wintypes.DWORD)]

    class TokenUser(ctypes.Structure):
        _fields_ = [("user", SidAndAttributes)]

    open_process_token = advapi32.OpenProcessToken
    open_process_token.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    open_process_token.restype = wintypes.BOOL
    get_token_information = advapi32.GetTokenInformation
    get_token_information.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_token_information.restype = wintypes.BOOL
    convert_sid = advapi32.ConvertSidToStringSidW
    convert_sid.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    convert_sid.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [wintypes.HLOCAL]
    local_free.restype = wintypes.HLOCAL

    token = wintypes.HANDLE()
    if not open_process_token(kernel32.GetCurrentProcess(), 0x8, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "cannot open current Windows process token")
    try:
        size = wintypes.DWORD()
        get_token_information(token, 1, None, 0, ctypes.byref(size))
        if not size.value:
            raise OSError(ctypes.get_last_error(), "cannot size current Windows token user")
        buffer = ctypes.create_string_buffer(size.value)
        if not get_token_information(token, 1, buffer, size.value, ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(), "cannot read current Windows token user")
        token_user = ctypes.cast(buffer, ctypes.POINTER(TokenUser)).contents
        sid_text = wintypes.LPWSTR()
        if not convert_sid(token_user.user.sid, ctypes.byref(sid_text)):
            raise OSError(ctypes.get_last_error(), "cannot encode current Windows user SID")
        try:
            return sid_text.value
        finally:
            local_free(ctypes.cast(sid_text, wintypes.HLOCAL))
    finally:
        close_handle(token)


def _set_windows_private_dacl(path: Path, user_sid: str) -> None:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    convert_sddl = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert_sddl.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.ULONG),
    ]
    convert_sddl.restype = wintypes.BOOL
    set_file_security = advapi32.SetFileSecurityW
    set_file_security.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.LPVOID]
    set_file_security.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [wintypes.HLOCAL]
    local_free.restype = wintypes.HLOCAL

    inheritance = "OICI" if path.is_dir() else ""
    sddl = f"D:P(A;{inheritance};FA;;;{user_sid})(A;{inheritance};FA;;;SY)"
    security_descriptor = wintypes.LPVOID()
    if not convert_sddl(sddl, 1, ctypes.byref(security_descriptor), None):
        raise OSError(ctypes.get_last_error(), f"cannot construct private Windows DACL for {path}")
    try:
        if not set_file_security(
            str(path),
            0x4 | 0x80000000,  # DACL + PROTECTED_DACL_SECURITY_INFORMATION
            security_descriptor,
        ):
            raise OSError(ctypes.get_last_error(), f"cannot apply private Windows DACL to {path}")
    finally:
        local_free(ctypes.cast(security_descriptor, wintypes.HLOCAL))


@contextlib.contextmanager
def _windows_component_handles(path: Path):
    """Hold non-reparse handles and detect component replacement during a write."""
    if os.name != "nt":
        yield
        return
    import ctypes
    from ctypes import wintypes

    create_file = ctypes.windll.kernel32.CreateFileW
    create_file.restype = wintypes.HANDLE
    close_handle = ctypes.windll.kernel32.CloseHandle
    get_info = ctypes.windll.kernel32.GetFileInformationByHandle
    invalid = wintypes.HANDLE(-1).value
    share = 0x1 | 0x2 | 0x4
    open_existing = 3
    flags = 0x02000000 | 0x00200000  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT

    class Info(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("created", wintypes.FILETIME),
            ("accessed", wintypes.FILETIME),
            ("written", wintypes.FILETIME),
            ("volume_serial", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD),
            ("index_low", wintypes.DWORD),
        ]

    def open_identity(component: Path):
        handle = create_file(str(component), 0, share, None, open_existing, flags, None)
        if handle == invalid:
            raise OSError(ctypes.get_last_error(), f"cannot secure path component {component}")
        info = Info()
        if not get_info(handle, ctypes.byref(info)):
            close_handle(handle)
            raise OSError(ctypes.get_last_error(), f"cannot inspect path component {component}")
        if info.attributes & 0x400:
            close_handle(handle)
            raise ValueError(f"symlink/reparse component {component}")
        identity = (info.volume_serial, info.index_high, info.index_low)
        return handle, identity

    components = []
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.exists():
            handle, identity = open_identity(current)
            components.append((current, handle, identity))
    try:
        yield
        for component, _, identity in components:
            check, current_identity = open_identity(component)
            close_handle(check)
            if current_identity != identity:
                raise ValueError(f"path component changed during secure write: {component}")
    finally:
        for _, handle, _ in reversed(components):
            close_handle(handle)


def harden_path(path: Path, *, executable: bool = False) -> None:
    """Apply owner-only permissions using the native platform authority."""
    if os.name != "nt":
        path.chmod(0o700 if path.is_dir() or executable else 0o600)
        return
    if not path.exists():
        raise FileNotFoundError(path)
    user_sid = _current_windows_user_sid()
    _set_windows_private_dacl(path, user_sid)
    sddl = _read_windows_sddl(path)
    try:
        _verify_private_sddl(sddl, user_sid, is_dir=path.is_dir())
    except PermissionError as exc:
        raise PermissionError(f"private Windows ACL verification failed for {path}: {exc}") from exc


class SecureRoot:
    """Contain files under an owner-only directory and verify before use."""

    def __init__(self, path: Path) -> None:
        expanded = path.expanduser()
        self.path = Path(os.path.abspath(expanded))

    @staticmethod
    def _is_link_or_reparse(path: Path) -> bool:
        try:
            info = path.lstat()
        except OSError:
            return False
        attributes = getattr(info, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag)

    @classmethod
    def _reject_link_components(cls, path: Path, *, message: str) -> None:
        current = Path(path.anchor)
        for component in path.parts[1:]:
            current /= component
            if cls._is_link_or_reparse(current):
                raise ValueError(f"{message}: symlink/reparse component {current}")

    def _lexically_contained(self, path: Path) -> Path:
        candidate = Path(os.path.abspath(path))
        if not candidate.is_relative_to(self.path):
            raise ValueError(f"path escapes secure root: {path}")
        return candidate

    def _resolved_root(self) -> Path:
        self._reject_link_components(self.path, message="secure root is a symlink")
        return self.path.resolve(strict=True)

    def ensure(self) -> SecureRoot:
        self._reject_link_components(self.path, message="secure root is a symlink")
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._reject_link_components(self.path, message="secure root is a symlink")
        harden_path(self.path)
        self.verify()
        return self

    def contained(self, relative: str | Path) -> Path:
        raw = Path(relative)
        candidate = self._lexically_contained(self.path / raw)
        self._reject_link_components(
            candidate.parent,
            message="path escapes secure root via symlink/reparse component",
        )
        resolved_parent = candidate.parent.resolve(strict=False)
        if not resolved_parent.is_relative_to(self._resolved_root()):
            raise ValueError(f"path escapes secure root: {relative}")
        return candidate

    def write_text(self, relative: str | Path, text: str) -> Path:
        if os.name != "nt":
            return self._write_text_unix(relative, text)
        path = self.contained(relative)
        with _windows_component_handles(self.path):
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            harden_path(path.parent)
            with _windows_component_handles(path.parent):
                if path.is_symlink():
                    raise ValueError(f"refusing symlink destination: {path}")
                atomic_write_text(path, text, new_file_mode=0o600)
                harden_path(path)
                self.verify(path)
        return path

    def make_directory(self, relative: str | Path) -> Path:
        """Create one private child directory through the root capability."""
        raw = Path(relative)
        if raw.is_absolute() or len(raw.parts) != 1 or raw.name in {"", ".", ".."}:
            raise ValueError(f"path escapes secure root: {relative}")
        self.verify()
        if os.name == "nt":
            path = self.contained(raw)
            with _windows_component_handles(self.path):
                path.mkdir(mode=0o700)
                harden_path(path)
                self.verify(path)
            return path
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        root_fd = os.open(self.path, flags)
        try:
            os.mkdir(raw.name, mode=0o700, dir_fd=root_fd)
            child_fd = os.open(raw.name, flags, dir_fd=root_fd)
            try:
                os.fchmod(child_fd, 0o700)
                os.fsync(root_fd)
            finally:
                os.close(child_fd)
        finally:
            os.close(root_fd)
        path = self.path / raw
        self.verify(path)
        return path

    def publish_directory(self, stage_relative: str | Path, final_relative: str | Path) -> Path:
        """Atomically publish a staged child without following root replacements."""
        stage = Path(stage_relative)
        final = Path(final_relative)
        if any(
            value.is_absolute() or len(value.parts) != 1 or value.name in {"", ".", ".."}
            for value in (stage, final)
        ):
            raise ValueError("published paths must be single secure-root components")
        self.verify(self.path / stage)
        if os.name == "nt":
            with _windows_component_handles(self.path):
                os.replace(self.contained(stage), self.contained(final))
        else:
            flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
            root_fd = os.open(self.path, flags)
            try:
                os.replace(
                    stage.name,
                    final.name,
                    src_dir_fd=root_fd,
                    dst_dir_fd=root_fd,
                )
                os.fsync(root_fd)
            finally:
                os.close(root_fd)
        published = self.path / final
        self.verify(published)
        return published

    def remove_directory(self, relative: str | Path) -> None:
        path = self.contained(relative)
        if path.exists():
            self.verify(path)
            shutil.rmtree(path)

    def _write_text_unix(self, relative: str | Path, text: str) -> Path:
        raw = Path(relative)
        if raw.is_absolute() or not raw.parts or any(part in {"", ".", ".."} for part in raw.parts):
            raise ValueError(f"path escapes secure root: {relative}")
        self.verify()
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        root_fd = os.open(self.path, flags)
        opened = [root_fd]
        temp_name = f".apm-secure-{secrets.token_hex(12)}"
        try:
            parent_fd = root_fd
            for part in raw.parts[:-1]:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(part, mode=0o700, dir_fd=parent_fd)
                try:
                    child_fd = os.open(part, flags, dir_fd=parent_fd)
                except OSError as exc:
                    raise ValueError(
                        f"path escapes secure root via symlink/reparse component: {part}"
                    ) from exc
                os.fchmod(child_fd, 0o700)
                opened.append(child_fd)
                parent_fd = child_fd
            leaf = raw.parts[-1]
            try:
                existing = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISLNK(existing.st_mode):
                    raise ValueError(f"refusing symlink destination: {self.path / raw}")
            except FileNotFoundError:
                pass
            fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_fd,
            )
            try:
                payload = normalize_crlf_to_lf(text).encode("utf-8")
                view = memoryview(payload)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
            os.replace(temp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            for fd in reversed(opened):
                os.close(fd)
            with contextlib.suppress(OSError):
                os.unlink(self.path.joinpath(*raw.parts[:-1], temp_name))
        path = self.path / raw
        self.verify(path)
        return path

    def verify(self, path: Path | None = None) -> None:
        original = self._lexically_contained(path or self.path)
        self._reject_link_components(
            original, message="path escapes secure root via symlink/reparse component"
        )
        target = original.resolve(strict=True)
        if not target.is_relative_to(self._resolved_root()):
            raise ValueError(f"path escapes secure root: {target}")
        if os.name != "nt":
            mode = stat.S_IMODE(target.stat().st_mode)
            expected = 0o700 if target.is_dir() else 0o600
            if mode & 0o077 or mode & expected != expected:
                raise PermissionError(f"insecure mode {mode:o} on {target}")
        else:
            harden_path(target)


def restore_file_bytes(path: Path, data: bytes, mode: int) -> None:
    """Atomically restore an existing native file without following components."""
    target = Path(os.path.abspath(path))
    SecureRoot._reject_link_components(
        target, message="activation restore path contains a symlink/reparse component"
    )
    if os.name == "nt":
        with _windows_component_handles(target.parent):
            if target.is_symlink():
                raise ValueError(f"activation restore destination is a symlink: {target}")
            atomic_write_bytes(target, data, new_file_mode=mode)
        return
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.open(target.parent, flags)
    temp_name = f".apm-restore-{secrets.token_hex(12)}"
    try:
        existing = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(existing.st_mode):
            raise ValueError(f"activation restore destination is a symlink: {target}")
        fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            mode,
            dir_fd=parent_fd,
        )
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temp_name, target.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
        with contextlib.suppress(OSError):
            os.unlink(target.parent / temp_name)
