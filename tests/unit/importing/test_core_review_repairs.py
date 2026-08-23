from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from apm_cli import config as apm_config
from apm_cli.cli import cli
from apm_cli.deps.lockfile import LockFile
from apm_cli.factory import ClientFactory
from apm_cli.importing import service
from apm_cli.importing.discovery import mapping_root, user_scope_mappings
from apm_cli.importing.plugin_discovery import PluginImport
from apm_cli.importing.service import ImportService
from apm_cli.integration.targets import KNOWN_TARGETS
from apm_cli.utils.content_hash import compute_file_hash


def _home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    return home


@pytest.mark.parametrize("source_args", [(), ("--from", "all")])
def test_public_global_default_and_all_leave_empty_home_untouched(
    monkeypatch, tmp_path, source_args
):
    home = _home(monkeypatch, tmp_path)
    monkeypatch.setattr(apm_config, "CONFIG_DIR", str(home / ".apm"))
    monkeypatch.setattr(apm_config, "CONFIG_FILE", str(home / ".apm/config.json"))
    monkeypatch.setattr(apm_config, "_config_cache", None)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("LOCALAPPDATA", str(home / "AppData/Local"))
    monkeypatch.setenv("APPDATA", str(home / "AppData/Roaming"))
    for name in (
        "APM_COPILOT_APP_DB",
        "APM_COPILOT_COWORK_SKILLS_DIR",
        "HERMES_HOME",
    ):
        monkeypatch.delenv(name, raising=False)
    candidate = tmp_path / "protocol/candidates.json"

    result = CliRunner().invoke(
        cli,
        ["import", "--global", *source_args, "--candidate-file", str(candidate)],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["kind"] == "import-plan"
    assert list(home.rglob("*")) == []


def _write_project_mcp(client: str, root: Path, name: str = "demo") -> Path | None:
    adapter = ClientFactory.create_client(client, project_root=root, user_scope=False)
    getter = getattr(adapter, "get_import_config_path", adapter.get_config_path)
    path = Path(getter()).expanduser()
    if not path.is_relative_to(root):
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".toml":
        path.write_text(
            f'[mcp_servers.{name}]\ncommand = "python"\nargs = ["-m", "{name}"]\n',
            encoding="utf-8",
        )
    else:
        path.write_text(
            json.dumps(
                {adapter.mcp_servers_key: {name: {"command": "python", "args": ["-m", name]}}}
            ),
            encoding="utf-8",
        )
    return path


@pytest.mark.parametrize(
    "client",
    ["antigravity", "claude", "codex", "cursor", "gemini", "kiro", "opencode", "vscode"],
)
def test_every_project_local_mcp_adapter_full_lifecycle(monkeypatch, tmp_path, client):
    home = _home(monkeypatch, tmp_path)
    monkeypatch.setenv("APM_E2E_TESTS", "1")
    root = tmp_path / client
    root.mkdir()
    assert _write_project_mcp(client, root) is not None
    candidate = tmp_path / f"protocol-{client}/candidates.json"
    plan = tmp_path / f"protocol-{client}/plan.json"

    first = ImportService().scan(
        sources=(client,),
        candidate_file=candidate,
        plan_json=plan,
        coordinator="standalone",
        project_root=root,
    )
    assert first["summary"] == {"local-package": 1}
    assert (
        ImportService().apply(
            candidate_file=candidate,
            plan_file=plan,
            coordinator="standalone",
            omni_preimage_set=None,
            token=None,
            project_root=root,
        )["state"]
        == "complete"
    )
    second = ImportService().scan(
        sources=(client,),
        candidate_file=tmp_path / f"second-{client}.json",
        plan_json=None,
        coordinator="standalone",
        project_root=root,
    )
    assert second["summary"] == {"already-managed": 1}
    assert not (home / ".apm/apm.yml").exists()


def test_mixed_project_mcp_clients_share_one_project_lifecycle(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    monkeypatch.setenv("APM_E2E_TESTS", "1")
    root = tmp_path / "mixed"
    root.mkdir()
    _write_project_mcp("codex", root, "codex-demo")
    _write_project_mcp("vscode", root, "vscode-demo")
    candidate = tmp_path / "mixed-protocol/candidates.json"
    plan = tmp_path / "mixed-protocol/plan.json"
    first = ImportService().scan(
        sources=("codex", "vscode"),
        candidate_file=candidate,
        plan_json=plan,
        coordinator="standalone",
        project_root=root,
    )
    assert first["summary"] == {"local-package": 2}
    ImportService().apply(
        candidate_file=candidate,
        plan_file=plan,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
        project_root=root,
    )
    second = ImportService().scan(
        sources=("codex", "vscode"),
        candidate_file=tmp_path / "mixed-second.json",
        plan_json=None,
        coordinator="standalone",
        project_root=root,
    )
    assert second["summary"] == {"already-managed": 2}


def test_sensitive_urls_and_option_assignments_never_serialize(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    secret = "never-serialize-this"
    config = home / ".codex/config.toml"
    config.parent.mkdir(parents=True)
    config.write_text(
        '[mcp_servers.bad]\nurl = "https://example.invalid/mcp?api-key='
        + secret
        + '"\nargs = ["--api-key='
        + secret
        + '"]\n',
        encoding="utf-8",
    )
    candidate = tmp_path / "secret/candidates.json"
    plan = tmp_path / "secret/plan.json"
    result = ImportService().scan(
        sources=("codex",),
        candidate_file=candidate,
        plan_json=plan,
        coordinator="standalone",
    )
    assert result["summary"] == {"secret-blocked": 1}
    assert secret not in candidate.read_text(encoding="utf-8")
    assert secret not in plan.read_text(encoding="utf-8")
    assert not (home / ".apm/apm.yml").exists()
    clean, blocked = service._sanitize(["https://e.invalid/?token=${TOKEN}", "--api-key=${TOKEN}"])
    assert clean == ["https://e.invalid/?token=${TOKEN}", "--api-key=${TOKEN}"]
    assert not blocked


@pytest.mark.skipif(os.name == "nt", reason="symlink creation differs on Windows")
def test_escaped_filesystem_and_mcp_paths_are_redacted_blockers(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "SKILL.md").write_text("outside-secret", encoding="utf-8")
    outside_file = tmp_path / "outside-agent.md"
    outside_file.write_text("outside-agent-secret", encoding="utf-8")
    skills = home / ".hermes/skills"
    skills.mkdir(parents=True)
    (skills / "evil").symlink_to(outside, target_is_directory=True)
    agents = home / ".claude/agents"
    agents.mkdir(parents=True)
    (agents / "evil.md").symlink_to(outside_file)
    result = ImportService().scan(
        sources=("claude", "hermes"),
        candidate_file=tmp_path / "escaped.json",
        plan_json=None,
        coordinator="standalone",
    )
    assert result["summary"] == {"unsupported": 2}
    raw = (tmp_path / "escaped.json").read_text(encoding="utf-8")
    assert "outside-secret" not in raw and "outside-agent-secret" not in raw
    assert str(outside) not in raw and str(outside_file) not in raw

    project = tmp_path / "project"
    project.mkdir()
    (project / ".vscode").symlink_to(outside, target_is_directory=True)
    blocked = ImportService().scan(
        sources=("vscode",),
        candidate_file=tmp_path / "mcp-escaped.json",
        plan_json=None,
        coordinator="standalone",
        project_root=project,
    )
    assert blocked["summary"] == {"unsupported": 1}


def test_malformed_mcp_hook_and_resolver_errors_share_blocker_contract(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    (home / ".codex").mkdir()
    (home / ".codex/config.toml").write_text("[[[", encoding="utf-8")
    (home / ".codex/hooks.json").write_text("{", encoding="utf-8")
    result = ImportService().scan(
        sources=("codex",),
        candidate_file=tmp_path / "malformed.json",
        plan_json=None,
        coordinator="standalone",
    )
    assert result["summary"] == {"unsupported": 2}
    assert all(item["proposed_action"] == "retain" for item in result["items"])

    broken = replace(
        KNOWN_TARGETS["copilot-cowork"],
        user_root_resolver=lambda: (_ for _ in ()).throw(OSError("sensitive path")),
    )
    monkeypatch.setitem(KNOWN_TARGETS, "copilot-cowork", broken)
    blocked = ImportService().scan(
        sources=("copilot-cowork",),
        candidate_file=tmp_path / "resolver.json",
        plan_json=None,
        coordinator="standalone",
    )
    assert blocked["summary"] == {"unsupported": 1}
    assert "sensitive path" not in (tmp_path / "resolver.json").read_text()


def test_unreadable_mcp_and_rejected_plugin_state_use_redacted_blockers(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    config = home / ".codex/config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('[mcp_servers.demo]\ncommand = "demo"\n', encoding="utf-8")
    adapter_type = type(ClientFactory.create_client("codex", user_scope=True))
    monkeypatch.setattr(
        adapter_type,
        "get_current_config",
        lambda self: (_ for _ in ()).throw(OSError("private detail")),
    )
    unreadable = ImportService().scan(
        sources=("codex",),
        candidate_file=tmp_path / "unreadable.json",
        plan_json=None,
        coordinator="standalone",
    )
    assert unreadable["summary"] == {"unsupported": 1}
    assert "private detail" not in (tmp_path / "unreadable.json").read_text()

    rejected = tmp_path / "do-not-read.json"
    rejected.write_text("plugin-secret", encoding="utf-8")
    monkeypatch.setattr(
        service,
        "discover_plugin_state",
        lambda roots: SimpleNamespace(
            plugins=(
                PluginImport(
                    "blocked",
                    rejected,
                    ("claude",),
                    "local-only",
                    {"unsupported_reason": "unsafe-plugin-state-path"},
                    (),
                    "unsafe-plugin-state-path",
                ),
            ),
            marketplaces=(),
        ),
    )
    candidates, preimages = service._discover_plugins(["claude"])
    assert preimages == []
    assert candidates[0]["payload"]["unsupported_reason"] == "unsafe-plugin-state-path"
    assert "plugin-secret" not in json.dumps(candidates)


def test_normal_global_lock_hashes_mark_outputs_managed_and_drift_visible(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    agent = home / ".claude/agents/demo.md"
    compiled = home / ".claude/CLAUDE.md"
    skill = home / ".agents/skills/shared/SKILL.md"
    plugin = home / ".claude/plugins/cache/demo/.claude-plugin/plugin.json"
    canvas = home / ".copilot/extensions/diagram/extension.mjs"
    hook = home / ".copilot/hooks/lifecycle-hooks.json"
    mcp = home / ".codex/config.toml"
    agent.parent.mkdir(parents=True)
    skill.parent.mkdir(parents=True)
    plugin.parent.mkdir(parents=True)
    canvas.parent.mkdir(parents=True)
    hook.parent.mkdir(parents=True)
    mcp.parent.mkdir(parents=True)
    agent.write_text("agent\n", encoding="utf-8")
    compiled.write_text("compiled\n", encoding="utf-8")
    skill.write_text("skill\n", encoding="utf-8")
    plugin.write_text('{"name":"demo-plugin"}\n', encoding="utf-8")
    canvas.write_text("export default {}\n", encoding="utf-8")
    hook.write_bytes(b'{"hooks":{"PreToolUse":[]}}\r\n')
    if os.name != "nt":
        canvas.chmod(0o755)
    mcp.write_text(
        '[mcp_servers.demo-mcp]\ncommand = "python"\nargs = ["-m", "demo"]\n',
        encoding="utf-8",
    )
    candidate = tmp_path / "before.json"
    ImportService().scan(
        sources=("claude", "codex", "copilot"),
        candidate_file=candidate,
        plan_json=None,
        coordinator="standalone",
    )
    envelope = json.loads(candidate.read_text(encoding="utf-8"))
    lock = LockFile()
    claimed_files = {
        item
        for preimage in envelope["source_preimages"]
        for path in [Path(preimage["absolute_path"])]
        for item in (
            [path] if path.is_file() else [entry for entry in path.rglob("*") if entry.is_file()]
        )
        if item.is_relative_to(home)
    }
    paths = sorted(item.relative_to(home).as_posix() for item in claimed_files)
    lock.local_deployed_files = paths
    lock.local_deployed_file_hashes = {path: compute_file_hash(home / path) for path in paths}
    apm = home / ".apm"
    apm.mkdir()
    mcp_candidates = [item for item in envelope["candidates"] if item["kind"] == "mcp"]
    lock.mcp_configs = {
        item["name"]: {"name": item["name"], **item["payload"]} for item in mcp_candidates
    }
    (apm / "apm.lock.yaml").write_text(lock.to_yaml(), encoding="utf-8")
    (apm / "apm.yml").write_text(
        "name: global\nversion: 1.0.0\ndependencies:\n  mcp:\n  - name: demo-mcp\n",
        encoding="utf-8",
    )

    managed = ImportService().scan(
        sources=("claude", "codex", "copilot"),
        candidate_file=tmp_path / "managed.json",
        plan_json=None,
        coordinator="standalone",
    )
    relevant = [
        item
        for item in managed["items"]
        if item["name"]
        in {
            "demo",
            "shared",
            "compiled-claude-md",
            "demo-plugin",
            "diagram",
            "lifecycle-hooks",
            "demo-mcp",
        }
    ]
    assert {item["classification"] for item in relevant} == {"already-managed"}
    assert {item["kind"] for item in relevant} >= {
        "agent",
        "skill",
        "instruction",
        "plugin",
        "package",
        "hook",
        "mcp",
    }
    agent.write_text("drift\n", encoding="utf-8")
    drift = ImportService().scan(
        sources=("claude",),
        candidate_file=tmp_path / "drift.json",
        plan_json=None,
        coordinator="standalone",
    )
    assert (
        next(item for item in drift["items"] if item["name"] == "demo")["classification"]
        == "local-package"
    )


def test_ownership_path_keys_normalize_windows_and_posix_separators(tmp_path):
    assert service._ownership_path_key(
        ".copilot\\hooks\\lifecycle-hooks.json", home=tmp_path
    ) == service._ownership_path_key(".copilot/hooks/lifecycle-hooks.json", home=tmp_path)


def _user_mapping_cases():
    return [
        pytest.param(target, kind, mapping, id=f"{target}-{kind}-{mapping.import_strategy}")
        for target, profile in sorted(KNOWN_TARGETS.items())
        if profile.user_supported
        for kind, mapping in sorted(user_scope_mappings(profile).items())
    ]


def _write_mapping_fixture(monkeypatch, tmp_path, home, target, kind, mapping):
    if target == "copilot-cowork":
        root = tmp_path / "cowork-skills"
        monkeypatch.setenv("APM_COPILOT_COWORK_SKILLS_DIR", str(root))
        path = root / "lifecycle" / "SKILL.md"
    else:
        profile = KNOWN_TARGETS[target].for_scope(user_scope=True) or KNOWN_TARGETS[target]
        base = mapping_root(profile, mapping, home=home) / mapping.subdir
        if mapping.extension.startswith("/"):
            path = base / "lifecycle" / mapping.extension[1:]
        elif mapping.extension.startswith("."):
            path = base / f"lifecycle-{kind}{mapping.extension}"
        elif mapping.extension:
            path = base / mapping.extension
        else:
            path = base / "lifecycle" / "extension.mjs"
    path.parent.mkdir(parents=True, exist_ok=True)
    if mapping.import_strategy == "snapshot":
        body = json.dumps({"hooks": {"PreToolUse": []}}) + "\n"
    elif mapping.format_id == "copilot_canvas":
        body = "export default {}\n"
    elif mapping.extension == ".toml":
        body = 'name = "lifecycle"\ndescription = "Lifecycle"\nprompt = "Do work"\n'
    else:
        body = "---\nname: lifecycle\ndescription: Lifecycle\n---\n# Lifecycle\n"
    path.write_text(body, encoding="utf-8")


@pytest.mark.parametrize(("target", "kind", "mapping"), _user_mapping_cases())
def test_every_user_mapping_full_lifecycle(monkeypatch, tmp_path, target, kind, mapping):
    if target == "copilot-app":
        from tests.unit.integration.test_copilot_app_workflow_import import (
            test_import_apply_audit_and_second_scan_are_lossless,
        )

        test_import_apply_audit_and_second_scan_are_lossless(monkeypatch, tmp_path)
        return

    home = _home(monkeypatch, tmp_path)
    monkeypatch.setenv("APM_E2E_TESTS", "1")
    _write_mapping_fixture(monkeypatch, tmp_path, home, target, kind, mapping)
    candidates = tmp_path / "protocol" / "candidates.json"
    plan_path = tmp_path / "protocol" / "plan.json"
    first = ImportService().scan(
        sources=(target,),
        candidate_file=candidates,
        plan_json=plan_path,
        coordinator="standalone",
    )
    envelope = json.loads(candidates.read_text(encoding="utf-8"))
    matching = [
        candidate for candidate in envelope["candidates"] if candidate["source_target"] == [target]
    ]
    assert matching, f"{target}:{kind}:{mapping.format_id} produced no exact-scope candidate"
    assert any(item["kind"] == matching[0]["kind"] for item in first["items"])
    if first["blockers"]:
        blocker_ids = {blocker["item_id"] for blocker in first["blockers"]}
        blockers = [item for item in first["items"] if item["id"] in blocker_ids]
        assert all(item["classification"] == "unsupported" for item in blockers)
        resolutions = {
            item["id"]: {**item["resolution"], "decision": "exclude"} for item in blockers
        }
        plan_path.write_text(json.dumps(service._plan(envelope, resolutions)), encoding="utf-8")

    result = ImportService().apply(
        candidate_file=candidates,
        plan_file=plan_path,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )
    assert result["state"] == "complete"

    second = ImportService().scan(
        sources=(target,),
        candidate_file=tmp_path / "protocol" / "second.json",
        plan_json=None,
        coordinator="standalone",
    )
    assert not [
        item
        for item in second["items"]
        if item["classification"] in {"importable", "local-package"}
    ]
