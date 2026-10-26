"""Executable approval gate helpers for the install pipeline.

Extracted from ``services.py`` to stay within the LOC budget.
These helpers are used by ``integrate_package_primitives`` to enforce
the npm v12-style ``allowExecutables`` default-deny policy.
"""

from __future__ import annotations

import builtins
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from apm_cli.core.command_logger import InstallLogger
    from apm_cli.install.context import InstallContext


def check_executable_approval(
    package_name: str,
    package_info: Any,
    allow_executables: builtins.dict[str, builtins.dict[str, bool]] | None,
    *,
    ctx: InstallContext | None = None,
    is_first_party: bool = False,
) -> tuple[bool, bool, bool, bool, bool, bool]:
    """Return hook, bin, MCP, canvas, LSP, and native extension approval.

    Legacy primitive gates preserve their opt-in enforcement when no approval
    block exists. Native extensions always require explicit approval unless
    the caller identifies real first-party project content.

    When *ctx* is provided and a package is blocked, the declaration is
    recorded on ``ctx.blocked_executables`` for the post-loop prompt.
    """
    if is_first_party:
        # Root-local authority is explicit. Dependency status scans must not
        # rediscover ambient target output as project executable declarations.
        return True, True, True, True, True, True
    is_local = package_name == "_local"
    legacy_unrestricted = allow_executables is None
    if allow_executables is None:
        allow_executables = {}

    from apm_cli.security.executables import (
        EXEC_TYPE_BIN,
        EXEC_TYPE_CANVAS,
        EXEC_TYPE_EXTENSIONS,
        EXEC_TYPE_HOOKS,
        EXEC_TYPE_LSP,
        EXEC_TYPE_MCP,
        is_package_approved,
    )

    # Executable authorization is bound to the resolver-owned dependency
    # identity. Package manifest metadata is display-only and must not become
    # an alternate security principal.
    pkg_key = resolve_package_key(package_info, package_name)
    candidate_keys = [pkg_key]

    name_blind = pkg_key.split("#", 1)[0]
    if name_blind not in candidate_keys:
        candidate_keys.append(name_blind)

    hooks_ok = any(
        is_package_approved(allow_executables, k, EXEC_TYPE_HOOKS) for k in candidate_keys
    )
    bin_ok = any(is_package_approved(allow_executables, k, EXEC_TYPE_BIN) for k in candidate_keys)
    mcp_ok = any(is_package_approved(allow_executables, k, EXEC_TYPE_MCP) for k in candidate_keys)
    canvas_ok = any(
        is_package_approved(allow_executables, k, EXEC_TYPE_CANVAS) for k in candidate_keys
    )
    lsp_ok = any(is_package_approved(allow_executables, k, EXEC_TYPE_LSP) for k in candidate_keys)
    extensions_ok = any(
        is_package_approved(allow_executables, k, EXEC_TYPE_EXTENSIONS) for k in candidate_keys
    )
    if is_local or legacy_unrestricted:
        # Preserve legacy local primitive trust, but native code requires the
        # resolver's first-party decision rather than a spoofable display name.
        hooks_ok = bin_ok = mcp_ok = canvas_ok = lsp_ok = True

    # Track blocked packages for the post-loop approval prompt, and record the
    # lockfile exec_status for the audit (Gap B) from the same scan.
    blocked = not all((hooks_ok, bin_ok, mcp_ok, canvas_ok, lsp_ok, extensions_ok))
    needs_status = ctx is not None and getattr(ctx, "exec_trust_ctx", None) is not None
    if ctx is not None and (blocked or needs_status):
        from apm_cli.security.executables import scan_package_executables

        _install = Path(package_info.install_path)
        _decl = scan_package_executables(
            _install,
            package_name,
            "",
            approval_identity=pkg_key,
        )
        approved_types = {
            EXEC_TYPE_HOOKS: hooks_ok,
            EXEC_TYPE_BIN: bin_ok,
            EXEC_TYPE_MCP: mcp_ok,
            EXEC_TYPE_CANVAS: canvas_ok,
            EXEC_TYPE_LSP: lsp_ok,
            EXEC_TYPE_EXTENSIONS: extensions_ok,
        }
        if any(not approved_types.get(kind, False) for kind in _decl.exec_types):
            ctx.blocked_executables.append(_decl)
        if _decl.has_executables and needs_status:
            from apm_cli.security.executables import exec_status_for_declaration

            status = exec_status_for_declaration(
                ctx.exec_trust_ctx, candidate_keys, _decl.exec_types
            )
            if status is not None:
                ctx.package_exec_status[package_name] = status

    return hooks_ok, bin_ok, mcp_ok, canvas_ok, lsp_ok, extensions_ok


def resolve_package_key(package_info: Any, package_name: str) -> str:
    """Build the ``allowExecutables`` lookup key for a package.

    Tries ``dependency_ref`` first (canonical dependency string), then
    falls back to ``name#version`` from the package's own metadata.
    """
    from apm_cli.security.executables import build_approval_key

    # Prefer the dependency reference's canonical string (includes version/ref)
    dep_ref = getattr(package_info, "dependency_ref", None)
    if dep_ref is not None:
        canonical = getattr(dep_ref, "canonical_string", None)
        if callable(canonical):
            cs = canonical()
            if cs:
                return cs
        # Fall back to str(dep_ref)
        s = str(dep_ref)
        if s:
            return s

    # Fall back to package metadata
    pkg = getattr(package_info, "package", None)
    if pkg is not None:
        name = getattr(pkg, "name", package_name) or package_name
        version = getattr(pkg, "version", "") or ""
        return build_approval_key(name, version)

    return package_name


def canvas_dependency_approved(package_info, package_name: str, allow_executables) -> bool:
    """Apply canvas dependency admission without the first-party name shortcut."""
    from apm_cli.security.executables import EXEC_TYPE_CANVAS, is_package_approved

    if allow_executables is None:
        return True
    return is_package_approved(
        allow_executables, resolve_package_key(package_info, package_name), EXEC_TYPE_CANVAS
    ) or is_package_approved(allow_executables, package_name, EXEC_TYPE_CANVAS)


def resolve_bin_skip(
    bin_approved: bool,
    trust_bin: bool | None,
    *,
    non_interactive: bool = False,
) -> tuple[bool, str | None]:
    """Combine executable approval with the ``--trust-bin`` posture."""
    if not bin_approved:
        return True, "not_approved"
    if trust_bin is False:
        return True, "not_trusted"
    if trust_bin is None and non_interactive:
        return True, "not_trusted"
    return False, None


def plugin_bin_deployable(
    package_info: Any,
    targets: list[Any],
    *,
    project_root: Path,
    scope: Any,
    policy: Any,
    skip_bin: bool,
) -> bool:
    """Return whether approved marketplace plugin bin files can reach a target."""
    from apm_cli.core.scope import InstallScope
    from apm_cli.models.apm_package import PackageType
    from apm_cli.security.executables import normalize_bin_deploy_deny_key

    if (
        skip_bin
        or package_info.package_type is not PackageType.MARKETPLACE_PLUGIN
        or scope is not InstallScope.USER
        or not (Path(package_info.install_path) / "bin").is_dir()
        or not any(
            target.name == "claude"
            and target.supports("skills")
            and (target.auto_create or (project_root / target.root_dir).is_dir())
            for target in targets
        )
    ):
        return False
    bin_policy = getattr(policy, "bin_deploy", None)
    if bin_policy is None:
        return True
    if bin_policy.deny_all:
        return False
    package_key = normalize_bin_deploy_deny_key(package_info.get_canonical_dependency_string())
    denied = {normalize_bin_deploy_deny_key(item) for item in bin_policy.deny}
    return package_key not in denied


def log_bin_status(
    skill_result: Any,
    suffix: str,
    package_name: str,
    package_info: Any,
    log_fn,
) -> None:
    """Emit integration-tree lines for bin/ deployment or skip reasons."""
    from apm_cli.utils.diagnostics import printable_ascii_text

    package_label = printable_ascii_text(package_name or getattr(package_info, "name", "unknown"))
    if skill_result.bin_deployed > 0:
        log_fn(
            f"  |-- {skill_result.bin_deployed} executable(s) deployed to "
            f"Claude Code's PATH -> {suffix} (invoked without confirmation)"
        )
        log_fn("  |-- run /reload-plugins or restart Claude Code to activate")
    elif skill_result.bin_skipped_reason == "project_scope":
        log_fn(
            "  |-- plugin ships executables; re-run with -g (global) to deploy them to Claude Code"
        )
    elif skill_result.bin_skipped_reason == "no_claude_target":
        log_fn(
            "  |-- plugin ships executables; no active Claude Code skills target to receive them"
        )
    elif skill_result.bin_skipped_reason == "not_approved":
        log_fn(
            f"  |-- bin/ executables skipped (not approved in allowExecutables). "
            f"Run 'apm approve {package_label}' to approve."
        )
    elif skill_result.bin_skipped_reason == "not_trusted":
        log_fn(
            "  |-- bin/ executables skipped (not trusted). "
            f"Run 'apm install --trust-bin {package_label}' to deploy."
        )
    elif skill_result.bin_skipped_reason == "not_retrusted_on_uninstall":
        log_fn(
            "  |-- bin/ executables not re-deployed during uninstall cleanup. "
            f"Run 'apm install --trust-bin {package_label}' to restore them."
        )


def filter_bundle_executable_files(
    pack_files: dict[str, str],
    *,
    allow_executables,
    approval_key: str | None,
    slug: str,
    create_config: bool,
    diagnostics,
    logger,
) -> int:
    """Remove blocked executable payloads in place and return reported skips.

    Native extensions always require exact bundle approval. Canvas retains its
    independent feature flag and legacy no-enforcement-block behavior.
    """
    from apm_cli.core.experimental import is_enabled
    from apm_cli.integration.canvas_integrator import is_canvas_bundle_path
    from apm_cli.integration.extension_discovery import is_native_extension_path
    from apm_cli.security.executables import (
        EXEC_TYPE_CANVAS,
        EXEC_TYPE_EXTENSIONS,
        is_package_approved,
    )

    skipped = 0
    extensions_approved = bool(allow_executables) and (
        approval_key is not None
        and is_package_approved(allow_executables, approval_key, EXEC_TYPE_EXTENSIONS)
    )
    if not extensions_approved:
        blocked_extensions = [rel for rel in pack_files if is_native_extension_path(rel)]
        for rel in blocked_extensions:
            pack_files.pop(rel)
        skipped += len(blocked_extensions)
        if blocked_extensions:
            message = f"Blocked native extensions from '{slug}': approve extensions for this exact bundle content."
            if diagnostics is not None:
                diagnostics.warn(message=message, package=str(slug))
            elif logger is not None:
                logger.warning(message)

    canvas_enabled = is_enabled("canvas", create_config=create_config)
    if canvas_enabled:
        canvas_approved = allow_executables is None or (
            approval_key is not None
            and is_package_approved(allow_executables, approval_key, EXEC_TYPE_CANVAS)
        )
    else:
        canvas_approved = False
    if not (canvas_enabled and canvas_approved):
        blocked = sorted(
            rel
            for rel in pack_files
            if is_canvas_bundle_path(rel) and not is_native_extension_path(rel)
        )
        if blocked:
            for rel in blocked:
                pack_files.pop(rel, None)
            if canvas_enabled:
                skipped += len(blocked)
                message = (
                    f"Blocked {len(blocked)} canvas extension file(s) from bundle "
                    f"'{slug}': canvas extensions are executable extension.mjs code "
                    "and are not approved for this exact bundle content. "
                    "Add this to apm.yml:\n"
                    "executables:\n"
                    "  allow:\n"
                    f'    "{approval_key}":\n'
                    "      canvas: true\n"
                    "Then rerun the install."
                )
                if diagnostics is not None:
                    diagnostics.warn(message=message, package=str(slug))
                elif logger is not None:
                    logger.warning(message)
    return skipped


def log_hooks_skip(package_name: str, package_info: Any, logger: InstallLogger | None) -> None:
    """Warn about skipped hooks only when the package actually ships them.

    Aligned with :meth:`HookIntegrator.find_hook_files`: checks for
    ``*.json`` in ``.apm/hooks/`` and ``hooks/``.
    """
    _install = Path(package_info.install_path)
    has_hooks = False
    for hook_dir in [_install / ".apm" / "hooks", _install / "hooks"]:
        if hook_dir.is_dir() and any(hook_dir.glob("*.json")):
            has_hooks = True
            break
    if not has_hooks:
        return
    _pkg_label = package_name or getattr(package_info, "name", "unknown")
    if logger:
        logger.warning(
            f"{_pkg_label}: hooks skipped (not approved in allowExecutables). "
            f"Run 'apm approve {_pkg_label}' to approve.",
            symbol="warning",
        )


def log_canvas_skip(package_name: str, package_info: Any, logger: InstallLogger | None) -> None:
    """Warn about skipped canvas extensions when the package ships them."""
    _install = Path(package_info.install_path)
    extensions_root = _install / ".apm" / "extensions"
    try:
        has_canvas = extensions_root.is_dir() and any(
            (d / "extension.mjs").is_file() for d in extensions_root.iterdir() if d.is_dir()
        )
    except OSError:
        has_canvas = False
    if not has_canvas:
        return
    _pkg_label = package_name or getattr(package_info, "name", "unknown")
    if logger:
        logger.warning(
            f"{_pkg_label}: canvas extension(s) skipped (not approved in allowExecutables). "
            f"Run 'apm approve {_pkg_label}' to approve.",
            symbol="warning",
        )


def log_extensions_skip(
    package_name: str,
    package_info: Any,
    targets,
    logger,
    diagnostics,
    *,
    is_first_party: bool,
) -> None:
    """Explain native precedence only for selected, declared native content."""
    from apm_cli.integration.extension_discovery import find_extension_bundles

    if any(target.supports("extensions") for target in targets) and find_extension_bundles(
        Path(package_info.install_path),
        validate_entries=False,
        is_first_party=is_first_party,
    ):
        message = (
            f"{package_name}: native extension deployment is gated; explicit "
            "extensions approval is required (canvas approval does not grant "
            "native execution). Native precedence means portable omp hooks "
            "are not selected for this package; they are not a fallback "
            "while the native replacement awaits approval."
        )
        if logger is not None:
            logger.warning(message)
        elif diagnostics is not None:
            diagnostics.warn(message=message, package=package_name)
