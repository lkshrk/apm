from __future__ import annotations

import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from apm_cli.importing.journal import read_journal
from apm_cli.importing.service import ImportProtocolError, ImportService
from apm_cli.install.locking import lifecycle_operation


def _home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    return home


def _scan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, coordinator: str = "standalone"):
    home = _home(monkeypatch, tmp_path)
    skill = home / ".agents" / "skills" / "demo"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: demo\n---\n# Demo\n", encoding="utf-8")
    output = tmp_path / "protocol"
    candidates = output / "candidates.json"
    plan = output / "plan.json"
    result = ImportService().scan(
        sources=("codex",),
        candidate_file=candidates,
        plan_json=plan,
        coordinator=coordinator,
    )
    return home, candidates, plan, result


def _candidate_envelope(importing, candidates: list[dict], preimages: list[dict]) -> dict:
    envelope = {
        "schema_version": 1,
        "coordinator": "standalone",
        "scope": "global",
        "sources": ["test"],
        "candidate_set_id": "",
        "source_preimages": preimages,
        "candidates": candidates,
    }
    envelope["candidate_set_id"] = importing._digest(
        {
            "sources": envelope["sources"],
            "preimages": preimages,
            "candidates": candidates,
        }
    )
    return envelope


def _local_candidate(importing, source: Path, candidate_id: str, **overrides):
    preimage = importing._preimage(source)
    candidate = {
        "id": candidate_id,
        "kind": "skill",
        "name": "shared",
        "root_id": "test-root",
        "source_handle": f"test:{candidate_id}",
        "source_target": ["claude"],
        "provenance": "local-only",
        "payload": {"source": "secured-path"},
        "content_fingerprint": preimage["content_fingerprint"],
        "source_preimage_ids": [preimage["id"]],
        "executable_paths": [],
    }
    candidate.update(overrides)
    return preimage, candidate


def test_scan_is_deterministic_and_only_writes_explicit_outputs(monkeypatch, tmp_path):
    home, candidates, plan, first = _scan(monkeypatch, tmp_path)
    before = sorted((p.relative_to(home), p.read_bytes()) for p in home.rglob("*") if p.is_file())
    second = ImportService().scan(
        sources=("codex",),
        candidate_file=candidates,
        plan_json=plan,
        coordinator="standalone",
    )
    after = sorted((p.relative_to(home), p.read_bytes()) for p in home.rglob("*") if p.is_file())
    assert first == second
    assert before == after
    if os.name != "nt":
        assert candidates.stat().st_mode & 0o077 == 0
        assert plan.stat().st_mode & 0o077 == 0
    schema_root = Path(__file__).parents[3] / "src" / "apm_cli" / "schemas"
    Draft202012Validator(
        json.loads((schema_root / "import-candidates-v1.json").read_text(encoding="utf-8"))
    ).validate(json.loads(candidates.read_text(encoding="utf-8")))
    Draft202012Validator(
        json.loads((schema_root / "import-plan-v1.json").read_text(encoding="utf-8"))
    ).validate(first)


def test_secret_payload_is_blocked_and_literal_never_serialized(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    claude = home / ".claude"
    claude.mkdir()
    secret = "do-not-leak-123"
    (claude / "settings.json").write_text(
        json.dumps({"mcpServers": {"private": {"command": "x", "env": {"TOKEN": secret}}}}),
        encoding="utf-8",
    )
    candidates = tmp_path / "out" / "candidates.json"
    plan = ImportService().scan(
        sources=("claude",), candidate_file=candidates, plan_json=None, coordinator="standalone"
    )
    assert secret not in candidates.read_text(encoding="utf-8")
    assert plan["summary"] == {"secret-blocked": 1}
    assert plan["blockers"]


def test_resolved_mcp_secrets_use_only_canonical_placeholder_fields():
    from apm_cli.importing import service as importing
    from apm_cli.models.dependency.mcp import MCPDependency

    payload = {
        "name": "secret-api",
        "registry": False,
        "transport": "http",
        "url": "https://example.invalid/mcp",
        "env": {"TOKEN": {"blocked": "literal-secret"}},
        "headers": {"X-API-Key": {"blocked": "literal-secret"}},
    }
    resolved = importing._apply_env_bindings(
        payload,
        {"/env/TOKEN": "MCP_TOKEN", "/headers/X-API-Key": "MCP_HEADER"},
    )
    canonical = importing._canonicalize_mcp_payload(resolved)
    assert canonical["env"] == {"TOKEN": "${MCP_TOKEN}"}
    assert canonical["headers"] == {"X-API-Key": "${MCP_HEADER}"}
    assert "env_literal" not in canonical
    assert "literal-secret" not in json.dumps(canonical)
    assert MCPDependency.from_dict(canonical).extra is None


def test_legacy_resolved_mcp_secret_containers_are_canonicalized():
    from apm_cli.importing import service as importing

    canonical = importing._canonicalize_mcp_payload(
        {
            "env_literal": {"TOKEN": "${MCP_TOKEN}"},
            "headers_literal": {"X-Key": "${MCP_HEADER}"},
            "authorization": "${MCP_AUTH}",
        }
    )
    assert canonical == {
        "env": {"TOKEN": "${MCP_TOKEN}"},
        "headers": {
            "X-Key": "${MCP_HEADER}",
            "Authorization": "${MCP_AUTH}",
        },
    }


def test_mapped_legacy_mcp_is_direct_manifest_dependency_and_locked(monkeypatch, tmp_path):
    from apm_cli.importing import service as importing

    home = _home(monkeypatch, tmp_path)
    monkeypatch.setenv("APM_E2E_TESTS", "1")
    source = tmp_path / "settings.json"
    source.write_text("{}", encoding="utf-8")
    preimage = importing._preimage(source)
    payload = {
        "name": "secret-api",
        "transport": "http",
        "url": "https://example.invalid/mcp",
        "env": {"TOKEN": {"blocked": "literal-secret"}},
    }
    candidate = {
        "id": "secret-api-candidate",
        "kind": "mcp",
        "name": "secret-api",
        "root_id": "omni-v24",
        "source_handle": "omni-v24:mcp:0",
        "source_target": ["codex"],
        "provenance": "unknown",
        "payload": payload,
        "content_fingerprint": importing._digest(payload),
        "source_preimage_ids": [preimage["id"]],
        "executable_paths": [],
        "secret_blocked": True,
    }
    envelope = _candidate_envelope(importing, [candidate], [preimage])
    item = importing._plan(envelope)["items"][0]
    reviewed = importing._plan(
        envelope,
        {
            item["id"]: {
                **item["resolution"],
                "decision": "map-secret",
                "env_bindings": {"/env/TOKEN": "MCP_TOKEN"},
            }
        },
    )
    protocol = tmp_path / "protocol"
    protocol.mkdir(mode=0o700)
    candidates = protocol / "candidates.json"
    plan = protocol / "plan.json"
    candidates.write_text(json.dumps(envelope), encoding="utf-8")
    plan.write_text(json.dumps(reviewed), encoding="utf-8")
    candidates.chmod(0o600)
    plan.chmod(0o600)

    result = ImportService().apply(
        candidate_file=candidates,
        plan_file=plan,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )
    assert result["state"] == "complete"
    manifest = yaml.safe_load((home / ".apm" / "apm.yml").read_text())
    assert manifest["dependencies"]["mcp"] == [
        {
            "name": "secret-api",
            "registry": False,
            "transport": "http",
            "url": "https://example.invalid/mcp",
            "env": {"TOKEN": "${MCP_TOKEN}"},
        }
    ]
    lock = (home / ".apm" / "apm.lock.yaml").read_text()
    assert "secret-api" in lock and "MCP_TOKEN" in lock
    assert "env_literal" not in lock and "literal-secret" not in lock


def test_standalone_apply_snapshots_and_adopts_manifest(monkeypatch, tmp_path):
    home, candidates, plan_path, plan = _scan(monkeypatch, tmp_path)
    result = ImportService().apply(
        candidate_file=candidates,
        plan_file=plan_path,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )
    assert result == {
        "schema_version": 1,
        "operation_id": plan["operation_id"],
        "coordinator": "standalone",
        "state": "complete",
        "next_action": "none",
        "finalize_token_required": False,
    }
    manifest = (home / ".apm" / "apm.yml").read_text(encoding="utf-8")
    assert str(home / ".apm" / "imported" / "skill") in manifest
    assert list((home / ".apm" / "imported" / "skill").glob("*/.apm/skills/demo/SKILL.md"))
    rerun = ImportService().apply(
        candidate_file=candidates,
        plan_file=plan_path,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )
    assert rerun == result


def test_omni_fence_and_idempotent_private_finalize(monkeypatch, tmp_path):
    _, candidates, plan_path, plan = _scan(monkeypatch, tmp_path, coordinator="omni-v24")
    token = b"a" * 32
    service = ImportService()
    result = service.apply(
        candidate_file=candidates,
        plan_file=plan_path,
        coordinator="omni-v24",
        omni_preimage_set="preimages-v24",
        token=token,
    )
    assert result["state"] == "awaiting-external-commit"
    assert result["finalize_token_required"] is True
    assert token.decode() not in json.dumps(service.status(plan["operation_id"]))
    with pytest.raises(RuntimeError, match="unresolved"):
        with lifecycle_operation():
            pass
    completed = service.finalize(
        operation_id=plan["operation_id"], omni_preimage_set="preimages-v24", token=token
    )
    assert completed["state"] == "complete"
    assert (
        service.finalize(
            operation_id=plan["operation_id"], omni_preimage_set="preimages-v24", token=token
        )
        == completed
    )
    with pytest.raises(ImportProtocolError, match="capability"):
        service.finalize(
            operation_id=plan["operation_id"],
            omni_preimage_set="preimages-v24",
            token=b"b" * 32,
        )


def test_apply_rejects_stale_source(monkeypatch, tmp_path):
    home, candidates, plan_path, _ = _scan(monkeypatch, tmp_path)
    (home / ".agents" / "skills" / "demo" / "SKILL.md").write_text("changed", encoding="utf-8")
    with pytest.raises(ImportProtocolError, match="stale source preimage"):
        ImportService().apply(
            candidate_file=candidates,
            plan_file=plan_path,
            coordinator="standalone",
            omni_preimage_set=None,
            token=None,
        )


def test_existing_omni_candidates_are_unioned_with_native_discovery(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    skill = home / ".agents" / "skills" / "native"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# Native\n", encoding="utf-8")
    legacy = tmp_path / "legacy.json"
    source = tmp_path / "settings.json"
    source.write_text("{}", encoding="utf-8")
    from apm_cli.importing import service as importing

    preimage = importing._preimage(source)
    candidate = {
        "id": "legacy-candidate",
        "kind": "package",
        "name": "legacy-package",
        "root_id": "omni-v24",
        "source_handle": "omni-v24:package:0",
        "source_target": ["claude"],
        "provenance": "remote",
        "payload": {"disposition": "excluded"},
        "content_fingerprint": preimage["content_fingerprint"],
        "source_preimage_ids": [preimage["id"]],
        "executable_paths": [],
    }
    envelope = {
        "schema_version": 1,
        "coordinator": "omni-v24",
        "scope": "global",
        "sources": ["omni-v24"],
        "candidate_set_id": "",
        "source_preimages": [preimage],
        "candidates": [candidate],
    }
    envelope["candidate_set_id"] = importing._digest(
        {
            "sources": envelope["sources"],
            "preimages": envelope["source_preimages"],
            "candidates": envelope["candidates"],
        }
    )
    legacy.write_text(json.dumps(envelope), encoding="utf-8")
    if os.name != "nt":
        legacy.chmod(0o600)
    plan_path = tmp_path / "legacy-plan.json"
    first_plan = ImportService().scan(
        sources=("claude", "codex"),
        candidate_file=legacy,
        plan_json=plan_path,
        coordinator="omni-v24",
    )
    merged = json.loads(legacy.read_text(encoding="utf-8"))
    assert merged["sources"] == ["claude", "codex", "omni-v24"]
    assert {item["name"] for item in merged["candidates"]} == {"legacy-package", "native"}
    legacy_item = next(item for item in first_plan["items"] if item["name"] == "legacy-package")
    assert legacy_item["classification"] == "excluded"
    assert legacy_item["reason_codes"] == ["legacy-negative-state"]
    service = ImportService()
    applied = service.apply(
        candidate_file=legacy,
        plan_file=plan_path,
        coordinator="omni-v24",
        omni_preimage_set="legacy-preimages",
        token=b"z" * 32,
    )
    service.finalize(
        operation_id=applied["operation_id"],
        omni_preimage_set="legacy-preimages",
        token=b"z" * 32,
    )
    second_plan = service.scan(
        sources=("claude", "codex"),
        candidate_file=legacy,
        plan_json=None,
        coordinator="omni-v24",
    )
    second_legacy = next(item for item in second_plan["items"] if item["name"] == "legacy-package")
    assert second_legacy["classification"] == "excluded"


def test_plugin_takeover_and_marketplace_registration(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    claude = home / ".claude"
    plugin = claude / "plugins" / "cache" / "demo-market" / "demo" / "1.0.0"
    (plugin / ".claude-plugin").mkdir(parents=True)
    (plugin / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "demo"}), encoding="utf-8"
    )
    (plugin / "commands").mkdir()
    (plugin / "commands" / "hello.md").write_text("# Hello\n", encoding="utf-8")
    (claude / "plugins" / "installed_plugins.json").write_text(
        json.dumps({"plugins": {"demo": [{"installPath": str(plugin)}]}}),
        encoding="utf-8",
    )
    (claude / "plugins" / "known_marketplaces.json").write_text(
        json.dumps({"demo-market": {"source": {"source": "github", "repo": "owner/repo"}}}),
        encoding="utf-8",
    )
    candidates = tmp_path / "protocol" / "candidates.json"
    plan_path = tmp_path / "protocol" / "plan.json"
    plan = ImportService().scan(
        sources=("claude",),
        candidate_file=candidates,
        plan_json=plan_path,
        coordinator="standalone",
    )
    assert {item["kind"] for item in plan["items"]} == {"plugin", "marketplace"}
    assert not plan["blockers"]
    result = ImportService().apply(
        candidate_file=candidates,
        plan_file=plan_path,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )
    assert result["state"] == "complete"
    installed = json.loads(
        (claude / "plugins" / "installed_plugins.json").read_text(encoding="utf-8")
    )
    assert "demo" not in installed["plugins"]
    registry = json.loads((home / ".apm" / "marketplaces.json").read_text(encoding="utf-8"))
    assert registry["marketplaces"] == [{"name": "demo-market", "owner": "owner", "repo": "repo"}]


@pytest.mark.parametrize("gate", ["_verify_post_retirement", "_audit_import"])
def test_plugin_activation_is_restored_when_post_retirement_gate_fails(monkeypatch, tmp_path, gate):
    from apm_cli.importing import service as importing

    home = _home(monkeypatch, tmp_path)
    claude = home / ".claude"
    plugin = claude / "plugins" / "cache" / "demo-market" / "demo" / "1.0.0"
    (plugin / ".claude-plugin").mkdir(parents=True)
    (plugin / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "demo"}), encoding="utf-8"
    )
    installed_path = claude / "plugins" / "installed_plugins.json"
    installed_path.write_text(
        json.dumps({"plugins": {"demo": [{"installPath": str(plugin)}]}}),
        encoding="utf-8",
    )
    (claude / "plugins" / "known_marketplaces.json").write_text(
        json.dumps({"demo-market": {"source": {"source": "github", "repo": "owner/repo"}}}),
        encoding="utf-8",
    )
    original = installed_path.read_bytes()
    original_mode = stat.S_IMODE(installed_path.stat().st_mode)
    candidates = tmp_path / "protocol" / "candidates.json"
    plan_path = tmp_path / "protocol" / "plan.json"
    plan = ImportService().scan(
        sources=("claude",),
        candidate_file=candidates,
        plan_json=plan_path,
        coordinator="standalone",
    )
    original_gate = getattr(importing, gate)
    monkeypatch.setattr(
        importing,
        gate,
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ImportProtocolError(f"{gate} failed")),
    )

    with pytest.raises(ImportProtocolError, match="failed"):
        ImportService().apply(
            candidate_file=candidates,
            plan_file=plan_path,
            coordinator="standalone",
            omni_preimage_set=None,
            token=None,
        )

    assert installed_path.read_bytes() == original
    assert stat.S_IMODE(installed_path.stat().st_mode) == original_mode
    journal = read_journal(plan["operation_id"])
    assert journal["phase"] == "ownership-verified"
    assert journal["state"] == "recoverable-partial"
    assert journal["retired_activations"] == []
    monkeypatch.setattr(importing, gate, original_gate)
    first = ImportService().resume(
        candidate_file=candidates,
        plan_file=plan_path,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )
    second = ImportService().resume(
        candidate_file=candidates,
        plan_file=plan_path,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )
    assert first["state"] == second["state"] == "complete"


def test_marketplace_dependency_supports_target_narrowing():
    from apm_cli.models.dependency.reference import DependencyReference

    dependency = DependencyReference.parse_from_dict(
        {"name": "demo", "marketplace": "demo-market", "targets": ["claude"]}
    )
    assert dependency.target_subset == ["claude"]


def test_marketplace_plugin_uses_registry_dependency_not_cache_snapshot(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    claude = home / ".claude"
    plugin = claude / "plugins" / "cache" / "demo-market" / "demo" / "1.0.0"
    (plugin / ".claude-plugin").mkdir(parents=True)
    (plugin / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "demo"}), encoding="utf-8"
    )
    (plugin / "commands").mkdir()
    (plugin / "commands" / "hello.md").write_text("# Hello\n", encoding="utf-8")
    (claude / "plugins" / "installed_plugins.json").write_text(
        json.dumps({"plugins": {"demo@demo-market": [{"installPath": str(plugin)}]}}),
        encoding="utf-8",
    )
    (claude / "plugins" / "known_marketplaces.json").write_text(
        json.dumps({"demo-market": {"source": {"source": "github", "repo": "owner/repo"}}}),
        encoding="utf-8",
    )
    candidates = tmp_path / "protocol" / "candidates.json"
    plan_path = tmp_path / "protocol" / "plan.json"
    plan = ImportService().scan(
        sources=("claude",),
        candidate_file=candidates,
        plan_json=plan_path,
        coordinator="standalone",
    )
    plugin_item = next(item for item in plan["items"] if item["kind"] == "plugin")
    assert plugin_item["classification"] == "importable"
    from apm_cli.importing import service as importing

    monkeypatch.setattr(importing, "_install_manifest", lambda *_args: None)
    monkeypatch.setattr(importing, "_audit_import", lambda *_args: None)
    ImportService().apply(
        candidate_file=candidates,
        plan_file=plan_path,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )
    manifest = yaml.safe_load((home / ".apm" / "apm.yml").read_text(encoding="utf-8"))
    assert {
        "name": "demo",
        "marketplace": "demo-market",
        "targets": ["claude"],
    } in manifest["dependencies"]["apm"]
    assert not (home / ".apm" / "imported" / "plugin").exists()


def test_legacy_unscoped_targets_block_before_mutation(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    source = tmp_path / "legacy.json"
    source.write_text("{}", encoding="utf-8")
    from apm_cli.importing import service as importing

    preimage = importing._preimage(source)
    candidate = {
        "id": "legacy-unscoped",
        "kind": "package",
        "name": "legacy-unscoped",
        "root_id": "omni-v24",
        "source_handle": "omni-v24:package:unscoped",
        "source_target": ["claude", "codex"],
        "provenance": "remote",
        "payload": {
            "dependency": "owner/package",
            "target_resolution_required": True,
        },
        "content_fingerprint": preimage["content_fingerprint"],
        "source_preimage_ids": [preimage["id"]],
        "executable_paths": [],
    }
    envelope = {
        "schema_version": 1,
        "coordinator": "omni-v24",
        "scope": "global",
        "sources": ["omni-v24"],
        "candidate_set_id": "",
        "source_preimages": [preimage],
        "candidates": [candidate],
    }
    envelope["candidate_set_id"] = importing._digest(
        {
            "sources": envelope["sources"],
            "preimages": envelope["source_preimages"],
            "candidates": envelope["candidates"],
        }
    )
    protocol = tmp_path / "protocol"
    protocol.mkdir(mode=0o700)
    candidate_path = protocol / "candidates.json"
    plan_path = protocol / "plan.json"
    candidate_path.write_text(json.dumps(envelope), encoding="utf-8")
    if os.name != "nt":
        candidate_path.chmod(0o600)
    plan = ImportService().scan(
        sources=(),
        candidate_file=candidate_path,
        plan_json=plan_path,
        coordinator="omni-v24",
    )
    item = plan["items"][0]
    assert item["classification"] == "needs-choice"
    assert item["proposed_action"] == "block"
    assert item["reason_codes"] == ["legacy-unscoped-targets"]
    assert plan["blockers"] == [
        {"item_id": item["id"], "reason_codes": ["legacy-unscoped-targets"]}
    ]
    with pytest.raises(ImportProtocolError, match="still contains blockers"):
        ImportService().apply(
            candidate_file=candidate_path,
            plan_file=plan_path,
            coordinator="omni-v24",
            omni_preimage_set="legacy-preimages",
            token=b"t" * 32,
        )
    assert not (home / ".apm").exists()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda plan: plan["items"][0].__setitem__("classification", "importable"),
        lambda plan: plan["warnings"].append("tampered"),
        lambda plan: plan["items"][0].__setitem__("proposed_targets", ["claude", "codex"]),
        lambda plan: plan.__setitem__("summary", {}),
    ],
)
def test_reviewed_plan_immutable_tamper_fails_before_apm_state(monkeypatch, tmp_path, mutate):
    home, candidates, plan_path, _ = _scan(monkeypatch, tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    mutate(plan)
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    if os.name != "nt":
        plan_path.chmod(0o600)
    with pytest.raises(ImportProtocolError, match="identity"):
        ImportService().apply(
            candidate_file=candidates,
            plan_file=plan_path,
            coordinator="standalone",
            omni_preimage_set=None,
            token=None,
        )
    assert not (home / ".apm").exists()


@pytest.mark.parametrize("gate", ["_verify_deployment", "_verify_post_retirement", "_audit_import"])
def test_verification_failures_never_reach_terminal_state(monkeypatch, tmp_path, gate):
    _, candidates, plan_path, plan = _scan(monkeypatch, tmp_path)
    from apm_cli.importing import service as importing

    monkeypatch.setattr(
        importing,
        gate,
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ImportProtocolError(f"{gate} failed")),
    )
    with pytest.raises(ImportProtocolError, match="failed"):
        ImportService().apply(
            candidate_file=candidates,
            plan_file=plan_path,
            coordinator="standalone",
            omni_preimage_set=None,
            token=None,
        )
    journal = read_journal(plan["operation_id"])
    assert journal["state"] == "recoverable-partial"


def test_same_operation_concurrent_apply_serializes(monkeypatch, tmp_path):
    _, candidates, plan_path, _ = _scan(monkeypatch, tmp_path)

    def apply_once():
        return ImportService().apply(
            candidate_file=candidates,
            plan_file=plan_path,
            coordinator="standalone",
            omni_preimage_set=None,
            token=None,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: apply_once(), range(2)))
    assert [result["state"] for result in results] == ["complete", "complete"]


def test_same_operation_concurrent_resume_serializes(monkeypatch, tmp_path):
    from apm_cli.importing import service as importing

    _, candidates, plan_path, _ = _scan(monkeypatch, tmp_path)
    original_write = importing.write_journal
    crashed = False

    def crash_once(journal):
        nonlocal crashed
        original_write(journal)
        if not crashed and journal.get("phase") == "backed-up":
            crashed = True
            raise RuntimeError("crash")

    monkeypatch.setattr(importing, "write_journal", crash_once)
    with pytest.raises(RuntimeError, match="crash"):
        ImportService().apply(
            candidate_file=candidates,
            plan_file=plan_path,
            coordinator="standalone",
            omni_preimage_set=None,
            token=None,
        )
    monkeypatch.setattr(importing, "write_journal", original_write)

    def resume_once():
        return ImportService().resume(
            candidate_file=candidates,
            plan_file=plan_path,
            coordinator="standalone",
            omni_preimage_set=None,
            token=None,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: resume_once(), range(2)))
    assert [result["state"] for result in results] == ["complete", "complete"]


def test_resolution_identity_is_independent_of_item_order():
    from apm_cli.importing import service as importing

    items = [
        {"id": "b", "resolution": dict(importing._EMPTY_RESOLUTION)},
        {
            "id": "a",
            "resolution": {**importing._EMPTY_RESOLUTION, "decision": "reuse"},
        },
    ]
    assert importing._resolution_identity(items) == importing._resolution_identity(
        list(reversed(items))
    )


@pytest.mark.parametrize(
    ("phase", "next_action"),
    [
        ("planned", "rollback"),
        ("backed-up", "rollback"),
        ("packages-staged", "rollback"),
        ("manifest-prepared", "rollback"),
        ("installed", "resume"),
        ("ownership-verified", "resume"),
        ("activation-retired", "resume"),
        ("post-retirement-verified", "resume"),
        ("audited", "resume"),
    ],
)
@pytest.mark.parametrize("boundary", ["before", "after"])
def test_crash_phase_replay_uses_the_required_recovery_side(
    monkeypatch, tmp_path, phase, next_action, boundary
):
    from apm_cli.importing import service as importing

    _, candidates, plan_path, plan = _scan(monkeypatch, tmp_path)
    original_write = importing.write_journal
    crashed = False

    class InjectedCrash(RuntimeError):
        pass

    def crash_around_phase_write(journal):
        nonlocal crashed
        if not crashed and boundary == "before" and journal.get("phase") == phase:
            crashed = True
            raise InjectedCrash(phase)
        original_write(journal)
        if not crashed and boundary == "after" and journal.get("phase") == phase:
            crashed = True
            raise InjectedCrash(phase)

    monkeypatch.setattr(importing, "write_journal", crash_around_phase_write)
    service = ImportService()
    with pytest.raises(InjectedCrash, match=phase):
        service.apply(
            candidate_file=candidates,
            plan_file=plan_path,
            coordinator="standalone",
            omni_preimage_set=None,
            token=None,
        )
    monkeypatch.setattr(importing, "write_journal", original_write)

    journal = read_journal(plan["operation_id"])
    assert journal is not None
    expected_phase = "ownership-verified" if phase == "post-retirement-verified" else phase
    assert journal["phase"] == expected_phase
    assert journal["state"] == "recoverable-partial"
    assert service.status(plan["operation_id"])["next_action"] == next_action

    replay = service.resume(
        candidate_file=candidates,
        plan_file=plan_path,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )
    assert replay["state"] == "complete"


@pytest.mark.parametrize("with_claude_md", [False, True])
def test_claude_hook_scripts_are_discovered_per_hook_file(monkeypatch, tmp_path, with_claude_md):
    home = _home(monkeypatch, tmp_path)
    claude = home / ".claude"
    hooks = claude / "hooks"
    scripts = claude / "scripts"
    hooks.mkdir(parents=True)
    scripts.mkdir()
    for name in ("one", "two"):
        script = scripts / f"{name}.sh"
        script.write_text("#!/bin/sh\n", encoding="utf-8")
        (hooks / f"{name}.json").write_text(
            json.dumps({"command": f"../scripts/{name}.sh"}), encoding="utf-8"
        )
    if with_claude_md:
        (claude / "CLAUDE.md").write_text("# User instructions\n", encoding="utf-8")

    plan = ImportService().scan(
        sources=("claude",),
        candidate_file=tmp_path / "candidates.json",
        plan_json=None,
        coordinator="standalone",
    )
    names = {item["name"] for item in plan["items"]}
    assert {"one-one", "two-two"}.issubset(names)
    assert ("compiled-claude-md" in names) is with_claude_md
    if with_claude_md:
        item = next(item for item in plan["items"] if item["name"] == "compiled-claude-md")
        assert item["classification"] == "local-package"


def test_conflict_selects_one_origin_and_excludes_losers(monkeypatch, tmp_path):
    from apm_cli.importing import service as importing

    home = _home(monkeypatch, tmp_path)
    sources = []
    candidates = []
    for candidate_id, body in (("origin-a", "# A\n"), ("origin-b", "# B\n")):
        source = tmp_path / candidate_id
        source.mkdir()
        (source / "SKILL.md").write_text(body, encoding="utf-8")
        preimage, candidate = _local_candidate(importing, source, candidate_id)
        sources.append(preimage)
        candidates.append(candidate)
    envelope = _candidate_envelope(importing, candidates, sources)
    protocol = tmp_path / "protocol"
    protocol.mkdir(mode=0o700)
    candidate_path = protocol / "candidates.json"
    plan_path = protocol / "plan.json"
    candidate_path.write_text(json.dumps(envelope), encoding="utf-8")
    candidate_path.chmod(0o600)
    plan = ImportService().scan(
        sources=(), candidate_file=candidate_path, plan_json=None, coordinator="standalone"
    )
    assert len(plan["items"]) == 1
    item = plan["items"][0]
    assert item["classification"] == "conflict"
    assert item["candidate_ids"] == ["origin-a", "origin-b"]
    resolution = {
        **item["resolution"],
        "decision": "select-origin",
        "selected_origin_id": "origin-b",
    }
    reviewed = importing._plan(envelope, {item["id"]: resolution})
    plan_path.write_text(json.dumps(reviewed), encoding="utf-8")
    plan_path.chmod(0o600)
    monkeypatch.setattr(importing, "_install_manifest", lambda *_args: None)
    monkeypatch.setattr(importing, "_audit_import", lambda *_args: None)
    result = ImportService().apply(
        candidate_file=candidate_path,
        plan_file=plan_path,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )
    assert result["state"] == "complete"
    imported = list((home / ".apm" / "imported" / "skill").glob("*"))
    assert len(imported) == 1
    assert (imported[0] / ".apm" / "skills" / "shared" / "SKILL.md").read_text() == "# B\n"
    assert [entry["id"] for entry in ImportService().list_exclusions()] == ["origin-a"]


def test_conflict_rejects_unknown_selected_origin(monkeypatch, tmp_path):
    from apm_cli.importing import service as importing

    _home(monkeypatch, tmp_path)
    preimages, candidates = [], []
    for candidate_id in ("a", "b"):
        source = tmp_path / candidate_id
        source.write_text(candidate_id, encoding="utf-8")
        preimage, candidate = _local_candidate(importing, source, candidate_id)
        preimages.append(preimage)
        candidates.append(candidate)
    envelope = _candidate_envelope(importing, candidates, preimages)
    item = importing._plan(envelope)["items"][0]
    reviewed = importing._plan(
        envelope,
        {
            item["id"]: {
                **item["resolution"],
                "decision": "select-origin",
                "selected_origin_id": "foreign",
            }
        },
    )
    protocol = tmp_path / "protocol"
    protocol.mkdir(mode=0o700)
    candidate_path = protocol / "candidates.json"
    plan_path = protocol / "plan.json"
    candidate_path.write_text(json.dumps(envelope), encoding="utf-8")
    plan_path.write_text(json.dumps(reviewed), encoding="utf-8")
    candidate_path.chmod(0o600)
    plan_path.chmod(0o600)
    with pytest.raises(ImportProtocolError, match="selected_origin_id"):
        ImportService().apply(
            candidate_file=candidate_path,
            plan_file=plan_path,
            coordinator="standalone",
            omni_preimage_set=None,
            token=None,
        )


def test_legacy_structured_skill_becomes_remote_dependency_not_snapshot():
    from apm_cli.importing import service as importing

    candidate = {
        "kind": "skill",
        "name": "legacy-review",
        "provenance": "unknown",
        "payload": {
            "name": "legacy-review",
            "source": "https://example.invalid/one",
            "ref": "main",
            "skill_path": "skills/review",
        },
    }
    assert importing._structured_dependency(candidate, ["claude"]) == {
        "git": "https://example.invalid/one",
        "ref": "main",
        "path": "skills/review",
        "alias": "legacy-review",
        "targets": ["claude"],
    }


def test_legacy_structured_file_source_becomes_local_dependency(tmp_path):
    from apm_cli.importing import service as importing

    repo = tmp_path / "repo"
    candidate = {
        "kind": "skill",
        "name": "legacy-review",
        "provenance": "unknown",
        "payload": {"source": repo.as_uri(), "skill_path": "skills/review"},
        "source_preimage_ids": [],
    }
    assert importing._structured_dependency(candidate, ["claude"]) == {
        "path": str(repo),
        "alias": "legacy-review",
        "targets": ["claude"],
    }


def test_windows_file_url_drive_is_absolute_source_path():
    from apm_cli.importing import service as importing

    assert importing._file_url_path("/C:/Users/test/repo", windows=True) == ("C:/Users/test/repo")


def test_conditional_candidate_can_be_explicitly_excluded(monkeypatch, tmp_path):
    from apm_cli.importing import service as importing

    home = _home(monkeypatch, tmp_path)
    source = tmp_path / "conditional.json"
    source.write_text("{}", encoding="utf-8")
    preimage, candidate = _local_candidate(
        importing,
        source,
        "conditional",
        kind="unsupported",
        payload={
            "target_resolution_required": True,
            "unsupported_reason": "conditional-group-host",
        },
        content_fingerprint=importing._digest(
            {
                "target_resolution_required": True,
                "unsupported_reason": "conditional-group-host",
            }
        ),
    )
    envelope = _candidate_envelope(importing, [candidate], [preimage])
    item = importing._plan(envelope)["items"][0]
    assert item["classification"] == "needs-choice"
    assert item["reason_codes"] == ["conditional-group-host"]
    reviewed = importing._plan(
        envelope,
        {item["id"]: {**item["resolution"], "decision": "exclude"}},
    )
    protocol = tmp_path / "protocol"
    protocol.mkdir(mode=0o700)
    candidate_path = protocol / "candidates.json"
    plan_path = protocol / "plan.json"
    candidate_path.write_text(json.dumps(envelope), encoding="utf-8")
    plan_path.write_text(json.dumps(reviewed), encoding="utf-8")
    candidate_path.chmod(0o600)
    plan_path.chmod(0o600)
    monkeypatch.setattr(importing, "_install_manifest", lambda *_args: None)
    monkeypatch.setattr(importing, "_audit_import", lambda *_args: None)
    ImportService().apply(
        candidate_file=candidate_path,
        plan_file=plan_path,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )
    assert not (home / ".apm" / "imported").exists()
    assert ImportService().list_exclusions()[0]["id"] == "conditional"


def test_exclusion_requires_matching_identity_scope_targets_and_fingerprint(monkeypatch, tmp_path):
    from apm_cli.importing import service as importing

    _home(monkeypatch, tmp_path)
    source = tmp_path / "source"
    source.write_text("content", encoding="utf-8")
    _, candidate = _local_candidate(importing, source, "stable")
    matching = importing._exclusion_entry(candidate, ["claude"])
    importing._write_exclusions({"stable": matching})
    assert (
        importing._plan(_candidate_envelope(importing, [candidate], [importing._preimage(source)]))[
            "items"
        ][0]["classification"]
        == "excluded"
    )

    for field, value in (
        ("root_id", "other-root"),
        ("source_target", ["codex"]),
        ("content_fingerprint", "f" * 64),
    ):
        changed = {**candidate, field: value}
        plan = importing._plan(
            _candidate_envelope(importing, [changed], [importing._preimage(source)])
        )
        assert plan["items"][0]["classification"] == "needs-choice"
        assert plan["items"][0]["reason_codes"] == ["excluded-changed"]

    foreign = {**matching, "id": "foreign", "name": "foreign"}
    importing._write_exclusions({"stable": matching, "foreign": foreign})
    assert {entry["id"] for entry in ImportService().list_exclusions()} == {
        "stable",
        "foreign",
    }
    remaining = ImportService().remove_exclusion("stable")
    assert [entry["id"] for entry in remaining] == ["foreign"]


def test_unmanaged_native_clients_require_explicit_durable_exclusion(monkeypatch, tmp_path):
    from apm_cli.importing import service as importing

    home = _home(monkeypatch, tmp_path)
    for relative in (".cursor/settings.json", ".kiro/settings/mcp.json"):
        path = home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
    (home / ".codeium" / "windsurf").mkdir(parents=True)
    protocol = tmp_path / "protocol"
    candidates_path = protocol / "candidates.json"
    plan_path = protocol / "plan.json"
    plan = ImportService().scan(
        sources=("claude", "codex"),
        candidate_file=candidates_path,
        plan_json=plan_path,
        coordinator="standalone",
    )
    unmanaged = [item for item in plan["items"] if item["classification"] == "unsupported"]
    assert {item["name"] for item in unmanaged} == {"cursor", "kiro"}
    assert {blocker["item_id"] for blocker in plan["blockers"]} == {
        item["id"] for item in unmanaged
    }
    candidates = json.loads(candidates_path.read_text(encoding="utf-8"))
    schema_root = Path(__file__).parents[3] / "src" / "apm_cli" / "schemas"
    Draft202012Validator(
        json.loads((schema_root / "import-candidates-v1.json").read_text(encoding="utf-8"))
    ).validate(candidates)
    reviewed = importing._plan(
        candidates,
        {item["id"]: {**item["resolution"], "decision": "exclude"} for item in unmanaged},
    )
    plan_path.write_text(json.dumps(reviewed), encoding="utf-8")
    plan_path.chmod(0o600)
    (home / ".cursor" / "changed-after-review").write_text("still unmanaged", encoding="utf-8")
    monkeypatch.setattr(importing, "_install_manifest", lambda *_args: None)
    monkeypatch.setattr(importing, "_audit_import", lambda *_args: None)
    ImportService().apply(
        candidate_file=candidates_path,
        plan_file=plan_path,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )
    assert {entry["name"] for entry in ImportService().list_exclusions()} == {
        "cursor",
        "kiro",
    }
    replay = ImportService().scan(
        sources=("claude", "codex"),
        candidate_file=candidates_path,
        plan_json=plan_path,
        coordinator="standalone",
    )
    assert replay["summary"] == {"excluded": 2}
    assert replay["blockers"] == []


def test_unmanaged_native_client_cannot_be_silently_reused(monkeypatch, tmp_path):
    from apm_cli.importing import service as importing

    home = _home(monkeypatch, tmp_path)
    cursor = home / ".cursor"
    cursor.mkdir()
    (cursor / "settings.json").write_text("{}", encoding="utf-8")
    candidates = tmp_path / "protocol" / "candidates.json"
    plan = tmp_path / "protocol" / "plan.json"
    ImportService().scan(
        sources=("claude", "codex"),
        candidate_file=candidates,
        plan_json=plan,
        coordinator="standalone",
    )
    before = sorted(
        (
            path.relative_to(home).as_posix(),
            path.lstat().st_mode,
            path.lstat().st_mtime_ns,
            path.read_bytes() if path.is_file() else None,
        )
        for path in home.rglob("*")
    )
    monkeypatch.setattr(importing, "_install_manifest", lambda *_args: None)
    monkeypatch.setattr(importing, "_audit_import", lambda *_args: None)
    with pytest.raises(ImportProtocolError, match="leave-unmanaged"):
        ImportService().apply(
            candidate_file=candidates,
            plan_file=plan,
            coordinator="standalone",
            omni_preimage_set=None,
            token=None,
        )
    after = sorted(
        (
            path.relative_to(home).as_posix(),
            path.lstat().st_mode,
            path.lstat().st_mtime_ns,
            path.read_bytes() if path.is_file() else None,
        )
        for path in home.rglob("*")
    )
    assert after == before
    assert not (home / ".apm").exists()
    assert ImportService().list_exclusions() == []


def test_snapshot_rejects_source_change_during_copy(monkeypatch, tmp_path):
    from apm_cli.importing import service as importing

    home, candidates, plan_path, _ = _scan(monkeypatch, tmp_path)
    source = home / ".agents" / "skills" / "demo" / "SKILL.md"
    original = importing._copy_source

    def copy_then_change(*args, **kwargs):
        original(*args, **kwargs)
        source.write_text("changed during copy", encoding="utf-8")

    monkeypatch.setattr(importing, "_copy_source", copy_then_change)
    with pytest.raises(ImportProtocolError, match="source changed while snapshotting"):
        ImportService().apply(
            candidate_file=candidates,
            plan_file=plan_path,
            coordinator="standalone",
            omni_preimage_set=None,
            token=None,
        )
    assert not list((home / ".apm" / "imported" / "skill").glob("demo-*"))


@pytest.mark.skipif(os.name == "nt", reason="Unix dirfd publish contract")
def test_snapshot_publish_rejects_import_root_swap(monkeypatch, tmp_path):
    from apm_cli.importing import secure

    _, candidates, plan_path, _ = _scan(monkeypatch, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    original = secure.SecureRoot.publish_directory

    def swap_then_publish(root, stage, final):
        detached = root.path.with_name(root.path.name + "-detached")
        os.replace(root.path, detached)
        root.path.symlink_to(outside, target_is_directory=True)
        return original(root, stage, final)

    monkeypatch.setattr(secure.SecureRoot, "publish_directory", swap_then_publish)
    with pytest.raises(ValueError, match="symlink/reparse"):
        ImportService().apply(
            candidate_file=candidates,
            plan_file=plan_path,
            coordinator="standalone",
            omni_preimage_set=None,
            token=None,
        )
    assert not any(outside.iterdir())
