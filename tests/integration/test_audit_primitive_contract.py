"""Real CLI and filesystem contracts for target-aware audit discovery."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path, PurePosixPath

import pytest
from click.testing import CliRunner

from apm_cli.cli import cli
from apm_cli.deps.lockfile import LockFile
from apm_cli.integration.targets import KNOWN_TARGETS
from apm_cli.policy.ci_checks import _check_content_integrity
from apm_cli.security.file_scanner import scan_project_result
from apm_cli.security.primitive_discovery import primitive_surfaces
from apm_cli.utils.content_hash import compute_file_hash
from tests.utils.isolated_apm_environment import IsolatedApmEnvironment
from tests.utils.lifecycle_state import LifecycleStateSnapshot

pytestmark = [pytest.mark.integration, pytest.mark.component]

_BIDI = "\u202e"
_SETTINGS = ".claude/settings.json"


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Bind every CLI call to isolated configuration, home and cache roots."""
    isolated = IsolatedApmEnvironment.create(tmp_path / "audit", base_env=os.environ)
    for key, value in isolated.subprocess_env().items():
        monkeypatch.setenv(key, value)
    root = isolated.work_root
    root.mkdir(parents=True, exist_ok=True)
    (root / "apm.yml").write_text("name: audit-contract\nversion: 1.0.0\ntarget: claude\n")
    LockFile().write(root / "apm.lock.yaml")
    monkeypatch.chdir(root)
    return root


def _write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _settings(root: Path, *, prompt: bool = False) -> Path:
    handlers = [{"type": "command", "command": f"touch NEVER_EXECUTE{_BIDI}"}]
    if prompt:
        handlers.append({"type": "prompt", "prompt": f"Check this {_BIDI}"})
    return _write(
        root,
        _SETTINGS,
        json.dumps(
            {
                "unrelated": _BIDI,
                "hooks": {"Stop": [{"matcher": _BIDI, "hooks": handlers}]},
            }
        ),
    )


@pytest.mark.parametrize("ci_mode", [False, True])
def test_shared_settings_command_inventory_is_visible_and_non_failing(
    project: Path, ci_mode: bool
) -> None:
    settings = _settings(project)
    before = settings.read_bytes()
    args = ["audit", "--no-drift", "--format", "json"]
    if ci_mode:
        args += ["--ci", "--no-policy", "--no-fail-fast"]
    result = CliRunner().invoke(cli, args)
    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    if ci_mode:
        check = next(c for c in report["checks"] if c["name"] == "content-integrity")
        assert any("discovered/untracked:" in detail for detail in check["details"])
        assert any("not-applicable" in detail for detail in check["details"])
    else:
        assert report["summary"]["files_scanned"] == 0
        assert report["findings"] == []
        entry = report["coverage"]["primitives"][0]
        assert entry["tracked"] is False
        assert entry["status"] == "not-applicable"
        assert entry["pointer"] == "/hooks/Stop/0/hooks/0"
    assert settings.read_bytes() == before
    assert not list(project.glob("NEVER_EXECUTE*"))


@pytest.mark.parametrize("output_format", ["text", "json", "sarif", "markdown"])
def test_decoded_prompt_fields_fail_without_scanning_unrelated_settings(
    project: Path, output_format: str
) -> None:
    settings = _settings(project, prompt=True)
    before = settings.read_bytes()
    result = CliRunner().invoke(cli, ["audit", "--no-drift", "--format", output_format])
    assert result.exit_code == 1, result.output
    assert "/hooks/Stop/0/hooks/1/prompt" in result.output
    assert settings.read_bytes() == before
    if output_format == "json":
        report = json.loads(result.output)
        assert report["summary"]["critical"] == 1
        assert report["summary"]["files_scanned"] == 1
        assert [entry["status"] for entry in report["coverage"]["primitives"]] == [
            "not-applicable",
            "checked",
        ]
    stripped = CliRunner().invoke(cli, ["audit", "--strip"])
    assert stripped.exit_code == 1
    assert "does not rewrite native configuration" in " ".join(stripped.output.split())
    assert settings.read_bytes() == before


@pytest.mark.parametrize(
    "payload",
    [
        '{"hooks":',
        '{"hooks":{"Stop":"invalid"}}',
        '{"hooks":{"Stop":[{"type":"future","prompt":"ignored"}]}}',
        '{"hooks":{"Stop":[{"type":"prompt","prompt":12}]}}',
        '{"hooks":{},"hooks":{}}',
        '{"hooks":{"Stop":[{"hooks":[{"hooks":[{"type":"prompt","prompt":"hidden"}]}]}]}}',
    ],
)
@pytest.mark.parametrize("ci_mode", [False, True])
def test_unknown_or_malformed_recognized_content_never_claims_success(
    project: Path, payload: str, ci_mode: bool
) -> None:
    settings = _write(project, _SETTINGS, payload)
    args = ["audit", "--no-drift", "--format", "json"]
    if ci_mode:
        args += ["--ci", "--no-policy", "--no-fail-fast"]
    result = CliRunner().invoke(cli, args)
    assert result.exit_code == 1, result.output
    report = json.loads(result.output)
    if ci_mode:
        check = next(c for c in report["checks"] if c["name"] == "content-integrity")
        assert check["passed"] is False
        assert any("incomplete-coverage:" in detail for detail in check["details"])
    else:
        assert report["passed"] is False
        assert report["coverage"]["complete"] is False
        assert report["findings"] == []
    assert settings.read_text() == payload


def test_unreadable_recognized_file_is_reported(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(project)
    read_text = Path.read_text

    def unreadable(path: Path, *args: object, **kwargs: object) -> str:
        if path == settings:
            raise PermissionError("fixture access denied")
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", unreadable)
    result = CliRunner().invoke(cli, ["audit", "--no-drift", "--format", "json"])
    assert result.exit_code == 1, result.output
    report = json.loads(result.output)
    assert report["coverage"]["primitives"][0]["status"] == "incomplete"
    assert report["summary"]["files_scanned"] == 0
    assert report["findings"] == []


def test_lockfile_membership_does_not_turn_a_script_into_prompt_text(project: Path) -> None:
    script = ".claude/hooks/scripts/run.py"
    _write(project, script, f"raise RuntimeError('NEVER_EXECUTE') # {_BIDI}")
    prompt = ".claude/skills/manual/SKILL.md"
    _write(project, prompt, f"Instruction {_BIDI}")
    lock = LockFile(local_deployed_files=[script, prompt])
    result = scan_project_result(project, lockfile=lock, targets=(KNOWN_TARGETS["claude"],))
    assert set(result.findings_by_file) == {prompt}
    inventory = {entry.file: entry for entry in result.inventory}
    assert inventory[script].status == "not-applicable"
    assert inventory[script].tracked is True
    assert inventory[prompt].status == "checked"
    assert inventory[prompt].tracked is True
    assert result.scanned_files == frozenset({prompt})


@pytest.mark.parametrize("target", sorted(KNOWN_TARGETS))
def test_registered_prompt_patterns_are_discovered(project: Path, target: str) -> None:
    profile = KNOWN_TARGETS[target]
    paths = set()
    surfaces = primitive_surfaces(project, (profile,))
    expected_kinds = set(profile.primitives) - {"hooks", "canvas"}
    assert expected_kinds <= {surface.kind for surface in surfaces}
    for surface in surfaces:
        if surface.kind == "hooks":
            continue
        path = (
            surface.path / surface.pattern.replace("*", "manual")
            if surface.pattern
            else surface.path
        )
        content = (
            "\n".join(f'{field} = "\\u202e"' for field in surface.prompt_fields)
            if surface.prompt_fields
            else _BIDI
        )
        _write(project, path.relative_to(project).as_posix(), content)
        paths.add(path.relative_to(project).as_posix())
    result = scan_project_result(project, targets=(profile,))
    assert paths
    assert set(result.findings_by_file) == paths
    assert result.incomplete == ()


def test_non_prompt_scripts_keep_hash_and_ownership_checks(project: Path) -> None:
    relative = ".claude/hooks/scripts/run.py"
    script = _write(project, relative, f"raise RuntimeError('NEVER_EXECUTE') # {_BIDI}")
    original_hash = compute_file_hash(script)
    lock_path = project / "apm.lock.yaml"
    LockFile(
        local_deployed_files=[relative],
        local_deployed_file_hashes={
            relative: original_hash,
        },
    ).write(lock_path)
    lock = LockFile.read(lock_path)
    assert lock is not None
    clean = _check_content_integrity(project, lock, (KNOWN_TARGETS["claude"],))
    assert clean.passed, clean.details
    script.write_text(f"# changed {_BIDI}", encoding="utf-8")
    tampered = _check_content_integrity(project, lock, (KNOWN_TARGETS["claude"],))
    assert not tampered.passed
    assert any(detail.startswith(f"hash-drift: {relative}") for detail in tampered.details)
    assert not any(detail.startswith("unicode:") for detail in tampered.details)


@pytest.mark.parametrize(
    "target,path,payload",
    [
        (
            "copilot",
            ".github/hooks/manual.json",
            '{"version":1,"hooks":{"sessionStart":[{"bash":"\\u202e"}]}}',
        ),
        (
            "claude",
            _SETTINGS,
            '{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"\\u202e"}]}]}}',
        ),
        (
            "gemini",
            ".gemini/settings.json",
            '{"hooks":{"AfterAgent":[{"hooks":[{"type":"command","command":"\\u202e"}]}]}}',
        ),
        (
            "codex",
            ".codex/hooks.json",
            '{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"\\u202e"}]}]}}',
        ),
        ("cursor", ".cursor/hooks.json", '{"version":1,"hooks":{"stop":[{"command":"\\u202e"}]}}'),
        (
            "windsurf",
            ".windsurf/hooks.json",
            '{"hooks":{"post_cascade_response":[{"command":"\\u202e"}]}}',
        ),
        (
            "kiro",
            ".kiro/hooks/manual.json",
            '{"version":"v1","hooks":[{"trigger":"agentStop","action":{"type":"command","command":"\\u202e"}}]}',
        ),
        (
            "antigravity",
            ".agents/hooks.json",
            '{"manual":{"PreToolUse":[{"hooks":[{"command":"\\u202e"}]}]}}',
        ),
    ],
)
def test_native_command_formats_are_inventory_not_prompt(
    project: Path, target: str, path: str, payload: str
) -> None:
    _write(project, path, payload)
    result = scan_project_result(project, targets=(KNOWN_TARGETS[target],))
    assert result.findings_by_file == {}
    assert result.scanned_files == frozenset()
    assert len(result.inventory) == 1
    assert result.inventory[0].status == "not-applicable"
    assert result.inventory[0].file == path


def test_excluded_transcripts_are_not_walked_or_read(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    skill = _write(project, ".claude/skills/manual/SKILL.md", _BIDI)
    transcripts = _write(project, ".claude/projects/session/log.jsonl", _BIDI * 1000)
    _write(project, ".claude/history.jsonl", _BIDI)
    walk = os.walk
    read_text = Path.read_text
    walks: list[Path] = []
    reads: list[Path] = []

    def bounded_walk(path: Path, *args: object, **kwargs: object) -> object:
        walks.append(Path(path))
        assert Path(path) != project / ".claude"
        assert not Path(path).is_relative_to(transcripts.parent.parent)
        return walk(path, *args, **kwargs)

    def bounded_read(path: Path, *args: object, **kwargs: object) -> str:
        reads.append(path)
        assert path.suffix != ".jsonl"
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(os, "walk", bounded_walk)
    monkeypatch.setattr(Path, "read_text", bounded_read)
    result = scan_project_result(project, targets=(KNOWN_TARGETS["claude"],))
    assert result.scanned_files == frozenset({".claude/skills/manual/SKILL.md"})
    assert skill in reads
    assert walks == [project / ".claude/skills"]


def test_directory_claims_use_native_applicability_without_tool_root_walk(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _settings(project, prompt=True)
    _write(
        project,
        ".claude/hooks/manual.json",
        '{"hooks":{"Stop":[{"hooks":[{"type":"prompt","prompt":"\\u202e"}]}]}}',
    )
    _write(project, ".claude/history/session.md", _BIDI)
    walk = os.walk

    def bounded_walk(path: Path, *args: object, **kwargs: object) -> object:
        assert Path(path) != project / ".claude"
        assert not Path(path).is_relative_to(project / ".claude/history")
        return walk(path, *args, **kwargs)

    monkeypatch.setattr(os, "walk", bounded_walk)
    result = scan_project_result(
        project,
        lockfile=LockFile(local_deployed_files=[".claude/hooks/", _SETTINGS]),
        targets=(KNOWN_TARGETS["claude"],),
        include_deployed_trees=False,
    )
    assert set(result.findings_by_file) == {_SETTINGS, ".claude/hooks/manual.json"}
    assert all(entry.tracked for entry in result.inventory)


@pytest.mark.parametrize(
    "target,relative,text,expected",
    [
        (
            "gemini",
            ".gemini/commands/manual.toml",
            'prompt = "\\u202e"\ndescription = "\\u202e"',
            True,
        ),
        (
            "codex",
            ".codex/agents/manual.toml",
            'developer_instructions = "\\u202e"\nname = "\\u202e"',
            True,
        ),
        (
            "kiro",
            ".kiro/hooks/manual.json",
            '{"version":"v1","hooks":[{"trigger":"agentStop","action":{"type":"agent","prompt":"\\u202e"}}]}',
            True,
        ),
        (
            "cursor",
            ".cursor/hooks.json",
            '{"version":1,"hooks":{"stop":[{"command":"\\u202e"}]}}',
            False,
        ),
        ("antigravity", ".agents/hooks.json", '{"manual":{"Stop":[{"command":"\\u202e"}]}}', False),
    ],
)
def test_native_formats_apply_only_documented_prompt_fields(
    project: Path, target: str, relative: str, text: str, expected: bool
) -> None:
    _write(project, relative, text)
    result = scan_project_result(project, targets=(KNOWN_TARGETS[target],))
    assert bool(result.findings_by_file) is expected
    assert not result.incomplete
    assert len(result.inventory) == 1
    assert result.inventory[0].tracked is False


def test_scope_resolved_external_root_and_symlink_boundaries(project: Path) -> None:
    external = project.parent / "external-claude"
    _write(external, "skills/manual/SKILL.md", _BIDI)
    _write(
        external,
        "settings.json",
        '{"hooks":{"Stop":[{"hooks":[{"type":"prompt","prompt":"\\u202e"}]}]}}',
    )
    outside = _write(project.parent, "outside/SKILL.md", _BIDI)
    (external / "skills" / "linked").symlink_to(outside.parent, target_is_directory=True)
    profile = replace(KNOWN_TARGETS["claude"], resolved_deploy_root=external)
    result = scan_project_result(project, targets=(profile,), user_scope=True)
    assert result.scanned_files == frozenset(
        {
            "claude:skills/manual/SKILL.md",
            "claude:settings.json",
        }
    )
    assert all("linked" not in entry.file for entry in result.inventory)
    assert result.protected_files == result.scanned_files


def test_audit_and_failures_preserve_complete_workspace_snapshot(project: Path) -> None:
    _settings(project, prompt=True)
    _write(project, ".claude/history.jsonl", _BIDI)
    configs = (PurePosixPath(_SETTINGS), PurePosixPath(".claude/history.jsonl"))
    before = LifecycleStateSnapshot.capture(project, targets=("claude",), config_paths=configs)
    for args in (
        ["audit", "--no-drift"],
        ["audit", "--ci", "--no-policy", "--no-drift", "--no-fail-fast"],
        ["audit", "--strip"],
    ):
        result = CliRunner().invoke(cli, args)
        assert result.exit_code == 1, result.output
        after = LifecycleStateSnapshot.capture(project, targets=("claude",), config_paths=configs)
        assert after == before


def test_symlink_prompt_is_never_read(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    outside = _write(project.parent, "outside-prompt.md", _BIDI)
    link = project / ".claude/rules/linked.md"
    link.parent.mkdir(parents=True)
    link.symlink_to(outside)
    read_text = Path.read_text

    def guarded_read(path: Path, *args: object, **kwargs: object) -> str:
        assert path not in {link, outside}, "audit followed a user symlink"
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read)
    result = scan_project_result(project, targets=(KNOWN_TARGETS["claude"],))
    assert result.scanned_files == frozenset()
    assert result.inventory == ()


@pytest.mark.parametrize("ci_mode", [False, True])
def test_lockless_cli_still_discovers_prompt_primitives(project: Path, ci_mode: bool) -> None:
    (project / "apm.lock.yaml").unlink()
    _write(project, ".claude/skills/manual/SKILL.md", _BIDI)
    args = ["audit", "--no-drift", "--format", "json"]
    if ci_mode:
        args += ["--ci", "--no-policy", "--no-fail-fast"]
    result = CliRunner().invoke(cli, args)
    assert result.exit_code == 1, result.output
    report = json.loads(result.output)
    if ci_mode:
        content = next(check for check in report["checks"] if check["name"] == "content-integrity")
        assert content["passed"] is False
        assert content["details"] == ["unicode: .claude/skills/manual/SKILL.md"]
    else:
        assert report["summary"]["critical"] == 1
        assert report["coverage"]["primitives"][0]["tracked"] is False
