"""APM-owned native Claude/Codex onboarding protocol."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import click

from apm_cli.importing import ImportProtocolError, ImportService

_OPERATION_ID = re.compile(r"^[a-f0-9]{32}$")


def _emit(payload: dict[str, Any]) -> None:
    click.echo(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def _emit_plan(plan: dict[str, Any]) -> None:
    _emit({"ok": True, "kind": "import-plan", "plan": plan})


def _emit_result(kind: str, result: dict[str, Any]) -> None:
    _emit({"ok": True, "kind": kind, "result": result})


def _token_from_stdin(enabled: bool) -> bytes | None:
    if not enabled:
        return None
    value = sys.stdin.buffer.read().strip()
    if not value:
        raise click.UsageError("--token-stdin requires a token on stdin")
    return value


def _path(value: str | None, option: str, *, required: bool = False) -> Path | None:
    if value is None:
        if required:
            raise click.UsageError(f"{option} is required")
        return None
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise click.UsageError(f"{option} must be absolute")
    return path


def _fail(exc: Exception, *, operation_id: str | None = None) -> None:
    from apm_cli.core.auth import redact_secrets

    code = "protocol-incompatible"
    exit_code = 5
    valid_operation = (
        operation_id if operation_id and _OPERATION_ID.fullmatch(operation_id) else None
    )
    if valid_operation:
        try:
            status = ImportService().status(valid_operation)
            if status["state"] == "recoverable-partial":
                code = "recoverable-partial"
                exit_code = 6
        except (ImportProtocolError, ValueError):
            pass
    error: dict[str, Any] = {"code": code, "message": redact_secrets(str(exc))}
    if valid_operation:
        error["operation_id"] = valid_operation
    _emit({"ok": False, "kind": "import-error", "error": error})
    raise click.exceptions.Exit(exit_code)


@click.group("import", invoke_without_command=True, help="Import existing native agent state")
@click.option("--global", "global_", is_flag=True, help="Import user-global state")
@click.option("--from", "sources", multiple=True, type=click.Choice(["claude", "codex"]))
@click.option("--candidate-file", type=click.Path(path_type=str))
@click.option("--plan-json", type=click.Path(path_type=str))
@click.option("--apply-plan", type=click.Path(path_type=str))
@click.option(
    "--coordinator",
    type=click.Choice(["standalone", "omni-v24"]),
    default="standalone",
    show_default=True,
)
@click.option("--omni-preimage-set")
@click.option("--token-stdin", is_flag=True)
@click.option("--format", "format_", type=click.Choice(["json"]), default="json")
@click.pass_context
def import_cmd(
    ctx: click.Context,
    global_: bool,
    sources: tuple[str, ...],
    candidate_file: str | None,
    plan_json: str | None,
    apply_plan: str | None,
    coordinator: str,
    omni_preimage_set: str | None,
    token_stdin: bool,
    format_: str,
) -> None:
    """Scan by default, or apply a reviewed plan with --apply-plan."""
    del format_
    if ctx.invoked_subcommand is not None:
        return
    if not global_:
        raise click.UsageError("native import currently requires --global")
    candidate_path = _path(candidate_file, "--candidate-file", required=bool(apply_plan))
    plan_path = _path(plan_json, "--plan-json")
    service = ImportService()
    try:
        if apply_plan:
            apply_path = _path(apply_plan, "--apply-plan", required=True)
            token = _token_from_stdin(token_stdin)
            plan_data = json.loads(apply_path.read_text(encoding="utf-8"))
            operation = str(plan_data.get("operation_id", "")) or None
            result = service.apply(
                candidate_file=candidate_path,
                plan_file=apply_path,
                coordinator=coordinator,
                omni_preimage_set=omni_preimage_set,
                token=token,
            )
        else:
            if not sources and not (candidate_path and candidate_path.is_file()):
                raise click.UsageError("scan requires --from or an existing --candidate-file")
            operation = None
            result = service.scan(
                sources=sources,
                candidate_file=candidate_path,
                plan_json=plan_path,
                coordinator=coordinator,
            )
        if apply_plan:
            _emit_result("import-apply-result", result)
        else:
            _emit_plan(result)
    except (ImportProtocolError, OSError, ValueError) as exc:
        _fail(exc, operation_id=locals().get("operation"))


@import_cmd.command("status", help="Read one import operation without mutation")
@click.option("--operation", required=True)
@click.option("--format", "format_", type=click.Choice(["json"]), default="json")
def status_cmd(operation: str, format_: str) -> None:
    del format_
    try:
        _emit_result("import-status-result", ImportService().status(operation))
    except (ImportProtocolError, ValueError) as exc:
        _fail(exc, operation_id=operation)


@import_cmd.command("resume", help="Resume an interrupted import")
@click.option("--operation", required=True)
@click.option("--candidate-file", required=True, type=click.Path(path_type=str))
@click.option("--apply-plan", required=True, type=click.Path(path_type=str))
@click.option("--coordinator", type=click.Choice(["standalone", "omni-v24"]), required=True)
@click.option("--omni-preimage-set")
@click.option("--token-stdin", is_flag=True)
@click.option("--format", "format_", type=click.Choice(["json"]), default="json")
def resume_cmd(
    operation: str,
    candidate_file: str,
    apply_plan: str,
    coordinator: str,
    omni_preimage_set: str | None,
    token_stdin: bool,
    format_: str,
) -> None:
    del format_
    try:
        result = ImportService().resume(
            candidate_file=_path(candidate_file, "--candidate-file", required=True),
            plan_file=_path(apply_plan, "--apply-plan", required=True),
            coordinator=coordinator,
            omni_preimage_set=omni_preimage_set,
            token=_token_from_stdin(token_stdin),
        )
        if result["operation_id"] != operation:
            raise ImportProtocolError("resume operation does not match reviewed plan")
        _emit_result("import-resume-result", result)
    except (ImportProtocolError, OSError, ValueError) as exc:
        _fail(exc, operation_id=operation)


@import_cmd.command("finalize", help="Finalize an externally coordinated import")
@click.option("--operation", required=True)
@click.option("--omni-preimage-set", required=True)
@click.option("--token-stdin", is_flag=True, required=True)
@click.option("--format", "format_", type=click.Choice(["json"]), default="json")
def finalize_cmd(operation: str, omni_preimage_set: str, token_stdin: bool, format_: str) -> None:
    del format_
    try:
        _emit_result(
            "import-finalize-result",
            ImportService().finalize(
                operation_id=operation,
                omni_preimage_set=omni_preimage_set,
                token=_token_from_stdin(token_stdin) or b"",
            ),
        )
    except (ImportProtocolError, OSError, ValueError) as exc:
        _fail(exc, operation_id=operation)


@import_cmd.command("rollback", help="Rollback an operation that has not installed")
@click.option("--operation", required=True)
@click.option("--format", "format_", type=click.Choice(["json"]), default="json")
def rollback_cmd(operation: str, format_: str) -> None:
    del format_
    try:
        _emit_result("import-rollback-result", ImportService().rollback(operation))
    except (ImportProtocolError, OSError, ValueError) as exc:
        _fail(exc, operation_id=operation)


@import_cmd.command("cleanup", help="Remove recoverable operation artifacts")
@click.option("--operation", required=True)
@click.option("--confirm", is_flag=True, required=True)
@click.option("--format", "format_", type=click.Choice(["json"]), default="json")
def cleanup_cmd(operation: str, confirm: bool, format_: str) -> None:
    del format_
    if not confirm:
        raise click.UsageError("cleanup requires --confirm")
    try:
        _emit_result("import-cleanup-result", ImportService().cleanup(operation))
    except (ImportProtocolError, OSError, ValueError) as exc:
        _fail(exc)


@import_cmd.group("exclusions", help="Inspect or remove durable import exclusions")
def exclusions_cmd() -> None:
    pass


@exclusions_cmd.command("list", help="List durable native-import exclusions")
@click.option("--format", "format_", type=click.Choice(["json"]), default="json")
def exclusions_list_cmd(format_: str) -> None:
    del format_
    try:
        _emit(
            {
                "ok": True,
                "kind": "import-exclusions-list",
                "exclusions": ImportService().list_exclusions(),
            }
        )
    except (ImportProtocolError, OSError, ValueError) as exc:
        _fail(exc)


@exclusions_cmd.command("remove", help="Remove one durable native-import exclusion")
@click.option("--id", "exclusion_id", required=True)
@click.option("--confirm", is_flag=True, required=True)
@click.option("--format", "format_", type=click.Choice(["json"]), default="json")
def exclusions_remove_cmd(exclusion_id: str, confirm: bool, format_: str) -> None:
    del format_
    if not confirm:
        raise click.UsageError("exclusion removal requires --confirm")
    try:
        _emit(
            {
                "ok": True,
                "kind": "import-exclusions-remove",
                "exclusions": ImportService().remove_exclusion(exclusion_id),
            }
        )
    except (ImportProtocolError, OSError, ValueError) as exc:
        _fail(exc)
