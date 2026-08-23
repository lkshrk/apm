"""Copilot App workflow deployment integrator.

The ``copilot-app`` target is the odd one out in the integrator
family: instead of writing files to disk (``.github/prompts/``,
``.claude/``, etc.) it inserts rows into the GitHub Copilot desktop
App's SQLite ``workflows`` table -- optionally via the App's own
WebSocket IPC surface when the App is running. The two surfaces
(file-based prompts vs. App-DB workflow rows) share NOTHING except
the source artefact (``*.prompt.md`` files in ``.apm/prompts/``).

This module owns the SQLite + WS-IPC path end-to-end. ``PromptIntegrator``
keeps a trivially small dispatch branch that constructs a
``CopilotAppWorkflowIntegrator`` and forwards the call -- one grep for
``copilot-app`` in ``prompt_integrator.py`` lands on that delegation.

Design notes
------------

* Inherits from ``BaseIntegrator`` for ``find_files_by_glob`` only;
  it does NOT use ``check_collision``, ``sync_remove_files``, or any
  of the file-based collision / link-resolution machinery. The
  workflow surface has its own collision model: ``deploy_workflow``
  is an UPSERT against a namespaced primary key, and sync deletes by
  id from the lockfile.
* Imports are top-level (no lazy imports). Pulling
  ``copilot_app_db`` / ``copilot_app_project`` / ``copilot_app_ws``
  here keeps ``prompt_integrator`` lightweight without paying any
  cost in the workflow path.
* Frontmatter helpers (``_is_workflow_shape``,
  ``_parse_workflow_frontmatter``, ``Schedule``,
  ``_derive_package_owner``) live in this module too: they are
  workflow-specific shape predicates. ``prompt_integrator`` and
  ``command_integrator`` import ``_is_workflow_shape`` from here for
  the dispatch-by-shape skip on the file-based side.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from apm_cli.integration import copilot_app_db as _db_mod
from apm_cli.integration import copilot_app_ws as _ws_mod
from apm_cli.integration.base_integrator import BaseIntegrator, IntegrationResult
from apm_cli.integration.copilot_app_db import (
    COPILOT_APP_LOCKFILE_PREFIX,
    CopilotAppDbError,
    WorkflowRow,
    from_lockfile_uri,
    is_copilot_app_uri,
    namespaced_id,
)
from apm_cli.integration.copilot_app_project import (
    derive_repo_context,
    resolve_or_register_project_sqlite,
)
from apm_cli.integration.copilot_app_ws import (
    WsAppNotRunning,
    WsAuthError,
    WsClient,
    WsError,
)
from apm_cli.utils.yaml_io import load_frontmatter, yaml_to_str

if TYPE_CHECKING:
    from apm_cli.integration.targets import TargetProfile


# ---------------------------------------------------------------------------
# Schedule frontmatter helpers (workflow-shape predicates)
# ---------------------------------------------------------------------------

_VALID_SCHEDULE_INTERVALS: frozenset[str] = frozenset({"manual", "hourly", "daily", "weekly"})
_VALID_SCHEDULE_MODES: frozenset[str] = frozenset({"interactive", "plan"})
"""Mirror of ``copilot_app_db._VALID_MODES``.  ``autopilot`` is
deliberately omitted -- see that module's docstring for the
secure-by-default rationale."""

# Top-level frontmatter keys that mark a ``.prompt.md`` as a "workflow"
# (i.e. a prompt with execution metadata, destined for the Copilot App
# DB rather than slash-command file targets).  Touching ANY of these
# keys at the top level of the frontmatter flips the dispatch shape.
#
# This is the Option B "dispatch by shape" predicate -- one folder
# (``.apm/prompts/``), one extension (``.prompt.md``), one integrator.
# A file with these keys ships to ``copilot-app`` and is skipped by
# slash-command targets; a file without them ships to slash-command
# targets and hard-errors at ``copilot-app``.
_WORKFLOW_SHAPE_KEYS: frozenset[str] = frozenset({"interval", "schedule_hour", "schedule_day"})
_IMPORTED_WORKFLOW_KEYS = frozenset(
    {
        "id",
        "name",
        "prompt",
        "model",
        "reasoning_effort",
        "project_id",
        "interval",
        "schedule_hour",
        "schedule_day",
        "enabled",
        "mode",
    }
)


def _load_imported_workflow(package_path: Path, prompt_files: list[Path]) -> dict | None:
    """Return a validated importer-owned workflow row, if present."""
    metadata_path = package_path / ".apm-import.json"
    if not metadata_path.exists():
        return None
    if not metadata_path.is_file() or metadata_path.is_symlink():
        raise ValueError("invalid imported Copilot App workflow metadata file")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("invalid imported Copilot App workflow metadata file") from exc
    if metadata.get("layout") != "workflow":
        return None

    imported_root = (Path.home() / ".apm" / "imported" / "command").resolve()
    row = metadata.get("workflow")
    candidate_ids = metadata.get("candidate_ids")
    fingerprint = metadata.get("content_fingerprint")
    operation_id = metadata.get("operation_id")
    if (
        not package_path.resolve().is_relative_to(imported_root)
        or metadata.get("schema_version") != 1
        or metadata.get("kind") != "command"
        or metadata.get("targets") != ["copilot-app"]
        or not isinstance(candidate_ids, list)
        or not candidate_ids
        or not all(isinstance(item, str) and item for item in candidate_ids)
        or not isinstance(metadata.get("root_id"), str)
        or not metadata["root_id"]
        or not isinstance(fingerprint, str)
        or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
        or not isinstance(operation_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", operation_id) is None
        or not isinstance(row, dict)
        or set(row) != _IMPORTED_WORKFLOW_KEYS
        or len(prompt_files) != 1
    ):
        raise ValueError("invalid imported Copilot App workflow metadata")

    string_fields = ("id", "name", "prompt", "interval")
    optional_strings = ("model", "reasoning_effort", "project_id", "mode")
    if (
        any(not isinstance(row[key], str) for key in string_fields)
        or any(row[key] is not None and not isinstance(row[key], str) for key in optional_strings)
        or row["interval"] not in _VALID_SCHEDULE_INTERVALS
        or row["mode"] not in {None, "interactive", "plan", "autopilot"}
        or type(row["schedule_hour"]) is not int
        or not 0 <= row["schedule_hour"] <= 23
        or type(row["schedule_day"]) is not int
        or not 0 <= row["schedule_day"] <= 6
        or type(row["enabled"]) is not int
        or row["enabled"] not in (0, 1)
    ):
        raise ValueError("invalid imported Copilot App workflow row")

    post = load_frontmatter(str(prompt_files[0]))
    expected_frontmatter = {
        key: row[key]
        for key in (
            "name",
            "interval",
            "schedule_hour",
            "schedule_day",
            "mode",
            "model",
            "reasoning_effort",
        )
        if row[key] is not None
    }
    expected_prompt = (
        f"---\n{yaml_to_str(expected_frontmatter, sort_keys=False).rstrip()}\n---\n{row['prompt']}"
    )
    if (
        post.metadata != expected_frontmatter
        or prompt_files[0].read_text(encoding="utf-8") != expected_prompt
    ):
        raise ValueError("imported Copilot App workflow snapshot does not match its metadata")
    return row


def _is_workflow_shape(frontmatter_meta: dict) -> bool:
    """Return True iff *frontmatter_meta* declares Copilot App execution metadata.

    Used to decide which target(s) a ``.prompt.md`` file is destined
    for.  The check is intentionally a SHAPE check rather than a flag
    -- authors do not opt in with a sentinel; the presence of an
    execution-affecting key is the opt-in.

    Only ``interval``, ``schedule_hour``, ``schedule_day`` are
    unambiguous workflow markers.  ``mode``, ``model``, and
    ``reasoning_effort`` are deliberately EXCLUDED because they overload
    with plain slash-command prompts: VSCode / Copilot prompts use
    ``mode: agent|ask|edit``, can pin a ``model``, and can hint
    ``reasoning_effort``.  Treating those keys as workflow markers
    would mis-route ordinary slash commands to the App DB.  Authors who
    want a manual-only workflow opt in with the explicit
    ``interval: manual``.
    """
    if not isinstance(frontmatter_meta, dict):
        return False
    return any(k in frontmatter_meta for k in _WORKFLOW_SHAPE_KEYS)


@dataclass(frozen=True)
class Schedule:
    """Validated representation of a prompt's workflow frontmatter.

    All fields are pre-validated against the same constraints the
    Copilot App's ``workflows`` schema enforces, so deploy time never
    surfaces a raw SQLite ``CHECK`` violation to the user.

    Sourced from top-level frontmatter keys (Option B: flat dispatch
    shape), not from a nested ``schedule:`` block.
    """

    interval: str = "manual"
    schedule_hour: int = 9
    schedule_day: int = 1
    mode: str | None = None
    model: str | None = None
    reasoning_effort: str | None = None


def _parse_workflow_frontmatter(meta: dict) -> Schedule:
    """Validate top-level workflow frontmatter keys and return a ``Schedule``.

    Reads ``interval``, ``schedule_hour``, ``schedule_day``, ``mode``,
    ``model``, ``reasoning_effort`` directly from the prompt's
    frontmatter.  ``interval`` defaults to ``"manual"`` when any other
    execution-shape key is present but ``interval`` is omitted -- a
    manual-only workflow is the conservative default given the Copilot
    App's universal "run now" affordance.

    Raises ``ValueError`` (with a human-readable message) on any
    out-of-range or wrong-type field.  ``mode: autopilot`` is rejected
    here with a targeted diagnostic before it can hit the DB layer's
    generic CHECK violation -- third-party packages cannot ship
    autopilot prompts; the user must opt in from the App UI.
    """
    if not isinstance(meta, dict):
        raise ValueError("frontmatter must be a mapping")

    interval = str(meta.get("interval", "manual"))
    if interval not in _VALID_SCHEDULE_INTERVALS:
        raise ValueError(
            f"interval must be one of {sorted(_VALID_SCHEDULE_INTERVALS)}, got {interval!r}"
        )

    hour = meta.get("schedule_hour", 9)
    if not isinstance(hour, int) or not (0 <= hour <= 23):
        raise ValueError(f"schedule_hour must be int 0..23, got {hour!r}")

    day = meta.get("schedule_day", 1)
    if not isinstance(day, int) or not (0 <= day <= 6):
        raise ValueError(f"schedule_day must be int 0..6, got {day!r}")

    mode = meta.get("mode")
    if mode is not None:
        mode = str(mode)
        if mode == "autopilot":
            raise ValueError(
                "mode 'autopilot' is not accepted via apm install -- "
                "APM does not deploy workflows on autopilot. "
                "Set autopilot manually in the Copilot App after enabling the row."
            )
        if mode not in _VALID_SCHEDULE_MODES:
            raise ValueError(f"mode must be one of {sorted(_VALID_SCHEDULE_MODES)}, got {mode!r}")

    model = meta.get("model")
    if model is not None and not isinstance(model, str):
        raise ValueError(f"model must be a string, got {model!r}")

    reasoning_effort = meta.get("reasoning_effort")
    if reasoning_effort is not None and not isinstance(reasoning_effort, str):
        raise ValueError(f"reasoning_effort must be a string, got {reasoning_effort!r}")

    return Schedule(
        interval=interval,
        schedule_hour=hour,
        schedule_day=day,
        mode=mode,
        model=model,
        reasoning_effort=reasoning_effort,
    )


# Back-compat alias retained for test imports; new code should use
# ``_parse_workflow_frontmatter`` directly.
_parse_schedule = _parse_workflow_frontmatter


def _derive_package_owner(package_info) -> str:
    """Best-effort owner-segment extraction for namespacing workflow ids.

    Looks at the package's ``source`` (GitHub-style ``owner/repo`` or
    URL) first, then ``author``, then falls back to ``"local"`` for
    locally-sourced packages.  The returned string is slugified by the
    DB-side ``namespaced_id`` helper, so any input is safe.
    """
    pkg = package_info.package
    source = getattr(pkg, "source", None)
    if isinstance(source, str) and source:
        # github:foo/bar, https://github.com/foo/bar, foo/bar
        s = source.split("://", 1)[-1]
        s = s.split(":", 1)[-1]
        parts = [p for p in s.split("/") if p and p != "github.com"]
        if parts:
            return parts[0]
    author = getattr(pkg, "author", None)
    if isinstance(author, str) and author.strip():
        return author.strip()
    return "local"


# ---------------------------------------------------------------------------
# Integrator
# ---------------------------------------------------------------------------


class CopilotAppWorkflowIntegrator(BaseIntegrator):
    """Deploy ``*.prompt.md`` workflow rows to the Copilot App DB.

    The integrator owns the full lifecycle of the ``copilot-app``
    target: prompt discovery, workflow-shape filtering, project
    resolution (WS-IPC preferred, SQLite fallback), and SQLite
    workflow-row UPSERT. It is constructed and called by
    ``PromptIntegrator.integrate_prompts_for_target`` when
    ``target.name == "copilot-app"``; nothing else routes here.
    """

    # ------------------------------------------------------------------
    # Prompt discovery (mirrors PromptIntegrator.find_prompt_files)
    # ------------------------------------------------------------------

    def find_prompt_files(self, package_path: Path) -> list[Path]:
        """Find all ``.prompt.md`` files in *package_path*.

        Same surface as ``PromptIntegrator.find_prompt_files`` -- the
        two integrators discover prompts identically; only the
        deploy-side is split. Re-defined here (instead of inheriting
        from ``PromptIntegrator``) to keep the workflow integrator
        decoupled from the file-based prompt integrator's other
        methods (``copy_prompt``, ``integrate_package_prompts``, ...).
        """
        return self.find_files_by_glob(package_path, "*.prompt.md", subdirs=[".apm/prompts"])

    # ------------------------------------------------------------------
    # Integrate
    # ------------------------------------------------------------------

    def integrate(
        self,
        target: TargetProfile,
        package_info,
        *,
        project_root: Path,
        user_scope: bool,
        force: bool,
        diagnostics,
    ) -> IntegrationResult:
        """Deploy workflow-shape prompts as Copilot App workflow rows.

        Hybrid dispatch:

        1. Detect the repo at ``project_root``. Derive a stable
           ``RepoContext`` (name, github owner/repo, default branch) so
           workflow rows scope to a real ``projects`` row instead of
           being orphaned at the root.
        2. If ``user_scope`` is set AND any workflow-shape prompts are
           present, emit a warn-and-proceed diagnostic: workflows run
           with CWD=~/.copilot in global mode, which is almost never
           what the user wants. We still deploy so global skills /
           commands keep working; the user can attach the row to a
           project from the App UI.
        3. If we COULD NOT detect a git repository at ``project_root``
           AND any workflow-shape prompts are present, emit a parallel
           warn-and-proceed diagnostic: workflows install with
           ``project_id=NULL`` which has the same CWD-pivot
           characteristic as ``--global``. The user can attach the row
           to a project from the App UI.
        4. Resolve the ``project_id`` ONCE: if the App is running
           (``ws_available``), try ``WsClient.create_project_from_path``
           so the project row goes through the App's own validation
           (owner/repo detection, default branch, account binding) and
           is already known to the webview. On any ``WsError`` (or if
           the App is closed) fall through to direct SQLite via
           ``resolve_or_register_project_sqlite``.
        5. Write every workflow row via direct SQLite
           (``copilot_app_db.deploy_workflow``), stamped with the
           resolved ``project_id`` and a namespaced
           ``owner/pkg/stem`` id so the lockfile stays stable across
           runs and across the WS-vs-SQLite project-resolution branch.
        6. If the project was freshly created (either branch), emit
           the one-time restart hint -- the webview's projectStore
           does not currently refresh on a new ``projects`` row.

        Workflow-shape (per ``_is_workflow_shape``) prompts deploy
        here.  Plain-shape prompts (no execution-affecting frontmatter
        keys) are a hard error at this target: the user explicitly
        opted into ``copilot-app`` for this package, and a plain
        prompt cannot possibly be a workflow.  Surfacing the mismatch
        loudly beats silently skipping the file and leaving the user
        wondering why nothing landed in the App.

        The DB module enforces ``enabled = 0`` for ordinary installs.
        Importer-owned snapshots can restore a previously reviewed native
        row exactly after their private ownership metadata is validated.
        """
        db_path = _db_mod.resolve_copilot_app_db_path()
        if db_path is None:
            return IntegrationResult(0, 0, 0, [])

        owner = _derive_package_owner(package_info)
        pkg_name = package_info.package.name

        # --------------------------------------------------------------
        # Parse all candidate prompts up front so we can decide on the
        # global-scope / no-repo warnings with one pass.
        # --------------------------------------------------------------
        prompt_files = self.find_prompt_files(package_info.install_path)
        imported_row = _load_imported_workflow(package_info.install_path, prompt_files)
        parsed: list[tuple[Path, object, Schedule]] = []
        files_skipped = 0
        for source_file in prompt_files:
            if source_file.is_symlink():
                if diagnostics is not None:
                    diagnostics.warn(
                        message=f"Refusing to read symlink prompt: {source_file}",
                        package=pkg_name,
                    )
                files_skipped += 1
                continue
            post = load_frontmatter(str(source_file))
            if imported_row is not None:
                parsed.append(
                    (
                        source_file,
                        post,
                        Schedule(
                            interval=imported_row["interval"],
                            schedule_hour=imported_row["schedule_hour"],
                            schedule_day=imported_row["schedule_day"],
                            mode=imported_row["mode"],
                            model=imported_row["model"],
                            reasoning_effort=imported_row["reasoning_effort"],
                        ),
                    )
                )
                continue
            if not _is_workflow_shape(post.metadata):
                if diagnostics is not None:
                    diagnostics.warn(
                        message=(
                            f"Copilot App: {source_file.name} has no workflow frontmatter "
                            "(missing one of: interval, schedule_hour, schedule_day). "
                            "Add `interval: manual` to deploy it as a manual-trigger "
                            "workflow, or unset --target copilot-app."
                        ),
                        package=pkg_name,
                    )
                files_skipped += 1
                continue
            try:
                schedule = _parse_workflow_frontmatter(post.metadata)
            except ValueError as exc:
                if diagnostics is not None:
                    diagnostics.warn(
                        message=f"Invalid workflow frontmatter in {source_file.name}: {exc}",
                        package=pkg_name,
                    )
                files_skipped += 1
                continue
            parsed.append((source_file, post, schedule))

        # --------------------------------------------------------------
        # --global + workflow-shape: warn but proceed.
        # --------------------------------------------------------------
        if imported_row is None and user_scope and parsed and diagnostics is not None:
            diagnostics.warn(
                message=(
                    "Copilot App workflows installed with --global run with CWD=~/.copilot, "
                    "not a project. Attach the workflow to a project from the App's Workflows "
                    "tab to fix this, or re-run `apm install` from a repo without --global. "
                    "See https://aka.ms/apm/copilot-app-global for details."
                ),
                package=pkg_name,
            )

        # --------------------------------------------------------------
        # Resolve project_id ONCE -- WS (preferred) then SQLite fallback.
        # --------------------------------------------------------------
        repo_ctx = None if imported_row is not None else derive_repo_context(project_root)
        repo_suffix = f" ({repo_ctx.repo_name})" if repo_ctx is not None else ""
        project_id: str | None = None
        was_created = False

        # --------------------------------------------------------------
        # No git repo + workflow-shape: same CWD-pivot risk as --global.
        # workflow rows land with project_id=NULL, which means "Run now"
        # CWDs into ~/.copilot. Warn parallel to the --global branch.
        # --------------------------------------------------------------
        if (
            imported_row is None
            and repo_ctx is None
            and parsed
            and not user_scope
            and diagnostics is not None
        ):
            diagnostics.warn(
                message=(
                    "Copilot App workflows installed without a project binding: "
                    "could not detect a git repository for this install. "
                    "Workflows will run with CWD=~/.copilot, not a project. "
                    "Re-run `apm install` from inside a git repo, or attach the "
                    "workflow to a project from the App's Workflows tab."
                ),
                package=pkg_name,
            )

        if repo_ctx is not None:
            if _ws_mod.ws_available():
                try:
                    with WsClient() as client:
                        project = client.create_project_from_path(repo_ctx.repo_root)
                    project_id = project.project_id
                    was_created = project.was_created
                except WsAppNotRunning:
                    # Race: ws_available() saw the port files but the
                    # App closed between probe and handshake. Silent
                    # fallback -- closed App is the normal off-state.
                    pass
                except WsAuthError:
                    # Stale ``ws.token`` -- most often because the App
                    # rotated its token at restart. We fall back to
                    # SQLite silently rather than nag on every install:
                    # the user-visible signal is already the restart
                    # hint emitted further down, and the SQLite path
                    # produces an identical project row.
                    pass
                except WsError as exc:
                    if diagnostics is not None:
                        diagnostics.warn(
                            message=(
                                f"Could not reach the running Copilot App "
                                f"({exc}). Registering the project directly "
                                "in the App database instead."
                            ),
                            package=pkg_name,
                        )

            if project_id is None:
                try:
                    resolved = resolve_or_register_project_sqlite(db_path, repo_ctx)
                    project_id = resolved.project_id
                    was_created = resolved.was_created
                except CopilotAppDbError as exc:
                    if diagnostics is not None:
                        diagnostics.warn(
                            message=(
                                f"Could not register project for Copilot App: {exc}. "
                                "Workflows will be installed without a project binding."
                            ),
                            package=pkg_name,
                        )

        if was_created and diagnostics is not None:
            # See github/github-app#5483 -- the App webview does not
            # currently refresh on externally-inserted ``projects``
            # rows. A one-time restart wires the new project into the
            # UI; subsequent installs into the same repo are silent.
            diagnostics.info(
                message=(
                    "Registered a new Copilot App project for this repo. "
                    "Restart the Copilot App once so the new project appears in the UI "
                    "(see github/github-app#5483)."
                ),
                package=pkg_name,
            )

        # --------------------------------------------------------------
        # Workflow rows -- always SQLite, regardless of project source.
        # Keeps lockfile ids namespaced and stable.
        # --------------------------------------------------------------
        synthetic_root = db_path.parent / "workflows"
        files_integrated = 0
        target_paths: list[Path] = []
        for source_file, post, schedule in parsed:
            prompt_stem = source_file.name.removesuffix(".prompt.md")
            wf_id = namespaced_id(owner, pkg_name, prompt_stem)
            if imported_row is not None:
                row = WorkflowRow(
                    id=wf_id, **{key: value for key, value in imported_row.items() if key != "id"}
                )
            else:
                base_name = post.metadata.get("name") or prompt_stem
                display_name = f"{base_name}{repo_suffix}"
                row = WorkflowRow(
                    id=wf_id,
                    name=str(display_name),
                    prompt=post.content,
                    interval=schedule.interval,
                    schedule_hour=schedule.schedule_hour,
                    schedule_day=schedule.schedule_day,
                    enabled=0,  # ALWAYS disabled on ordinary install -- contract.
                    model=schedule.model,
                    reasoning_effort=schedule.reasoning_effort,
                    mode=schedule.mode,
                    project_id=project_id,
                )
            try:
                _db_mod.deploy_workflow(
                    db_path,
                    row,
                    preserve_imported_state=imported_row is not None,
                    source_workflow_id=imported_row["id"] if imported_row is not None else None,
                )
            except CopilotAppDbError as exc:
                if diagnostics is not None:
                    diagnostics.warn(
                        message=f"Could not deploy {prompt_stem!r} to Copilot App: {exc}",
                        package=pkg_name,
                    )
                files_skipped += 1
                continue
            files_integrated += 1
            target_paths.append(synthetic_root / wf_id)

        return IntegrationResult(
            files_integrated=files_integrated,
            files_updated=0,
            files_skipped=files_skipped,
            target_paths=target_paths,
            links_resolved=0,
            files_adopted=0,
        )

    # ------------------------------------------------------------------
    # Sync (uninstall)
    # ------------------------------------------------------------------

    def sync(self, managed_files: set[str]) -> dict[str, int]:
        """Remove Copilot App workflow rows referenced by *managed_files*.

        Filters the input set to ``copilot-app-db://workflows/`` URIs,
        decodes the workflow ids, and deletes them in a single
        transaction.  Non-APM-namespaced ids are rejected by
        ``copilot_app_db.delete_workflows`` for defence in depth.
        """
        ids: list[str] = []
        for entry in managed_files:
            if not is_copilot_app_uri(entry):
                continue
            if not entry.startswith(COPILOT_APP_LOCKFILE_PREFIX):
                continue
            try:
                ids.append(from_lockfile_uri(entry))
            except ValueError:
                # Malformed entry -- skip rather than fail uninstall.
                continue
        if not ids:
            return {"files_removed": 0, "errors": 0}

        db_path = _db_mod.resolve_copilot_app_db_path()
        if db_path is None:
            # DB gone -- nothing to remove; treat as success (idempotent).
            return {"files_removed": 0, "errors": 0}

        try:
            removed = _db_mod.delete_workflows(db_path, ids)
        except CopilotAppDbError:
            return {"files_removed": 0, "errors": 1}
        return {"files_removed": removed, "errors": 0}
