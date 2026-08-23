import json
import os
import stat
from pathlib import Path

import yaml

from apm_cli.importing import service
from apm_cli.importing.discovery import NativeResource
from apm_cli.importing.plugin_discovery import MarketplaceImport, PluginDiscovery, PluginImport


def _home(monkeypatch, tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return home


def _item(*approved: str) -> dict:
    return {"resolution": {"approved_executables": list(approved)}}


def test_compiled_snapshot_uses_private_native_layout(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    root = tmp_path / ".claude"
    source = root / "rules" / "raw.md"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"first\r\nlast")
    preimage, candidate = service._candidate(
        service._Root("claude-config", "claude", root),
        source,
        "instruction",
        "raw",
        {
            "import_layout": "compiled-instruction",
            "target": "claude",
            "format_id": "claude_rules",
            "relative_path": "rules/raw.md",
        },
    )

    package = service._snapshot(candidate, _item(), source, preimage, "op")

    assert (
        package / ".apm/native/instructions/claude/rules/raw.md"
    ).read_bytes() == b"first\r\nlast"
    metadata = json.loads((package / ".apm-import.json").read_text())
    assert metadata | {"operation_id": "op"} == metadata
    assert metadata["layout"] == "compiled-instruction"
    assert package.is_relative_to(home / ".apm/imported")


def test_claude_compiled_singleton_is_discovered_once(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    claude_md = home / ".claude/CLAUDE.md"
    claude_md.parent.mkdir(parents=True)
    claude_md.write_bytes(b"singleton\r\nbytes")

    candidates, _ = service._discover_targets(["claude"])
    found = [item for item in candidates if item["name"] == "compiled-claude-md"]

    assert len(found) == 1
    assert found[0]["payload"] == {
        "import_layout": "compiled-instruction",
        "target": "claude",
        "format_id": "claude_rules",
        "relative_path": "CLAUDE.md",
    }


def test_workflow_snapshot_preserves_supported_row_fields(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    db = tmp_path / "workflows.db"
    db.write_bytes(b"sqlite")
    row = {
        "id": "native",
        "name": "Daily",
        "prompt": "Do work\n",
        "interval": "daily",
        "schedule_hour": 7,
        "schedule_day": 2,
        "mode": "plan",
        "model": "model",
        "reasoning_effort": "high",
        "project_id": None,
        "enabled": 0,
    }
    preimage, candidate = service._candidate(
        service._Root("copilot-app-config", "copilot-app", tmp_path),
        db,
        "command",
        "native",
        {"import_layout": "workflow", "workflow": row},
    )

    package = service._snapshot(candidate, _item(), db, preimage, "op")
    prompt = next((package / ".apm/prompts").glob("*.prompt.md")).read_text()

    assert "interval: daily" in prompt
    assert "schedule_hour: 7" in prompt
    assert prompt.endswith("Do work\n")
    assert json.loads((package / ".apm-import.json").read_text())["workflow"] == row


def test_grouped_hook_snapshot_keeps_scripts_in_one_package(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    root = tmp_path / ".codex"
    script = root / "hooks/scripts/check.sh"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\n")
    script.chmod(0o755)
    descriptor = root / "hooks.json"
    descriptor.write_text(json.dumps({"hooks": {"PreToolUse": [{"command": str(script)}]}}))
    native = NativeResource(root, descriptor, "hook", "codex-hooks", ("codex",), "snapshot")
    monkeypatch.setattr(service, "discover_filesystem_resources", lambda _targets: [native])

    candidates, preimages = service._discover_filesystem_targets(["codex"])
    candidate = candidates[0]
    preimages_by_id = {item["id"]: item for item in preimages}
    package = service._snapshot(
        candidate,
        _item("hooks/scripts/check.sh"),
        descriptor,
        preimages[0],
        "op",
        preimages_by_id,
    )

    assert len(candidate["source_preimage_ids"]) == 2
    copied = package / ".apm/hooks/resources/hooks/scripts/check.sh"
    assert copied.read_bytes() == script.read_bytes()
    if os.name != "nt":
        assert stat.S_IMODE(copied.stat().st_mode) & 0o111
    rendered = json.loads(next((package / ".apm/hooks").glob("*.json")).read_text())
    assert "./resources/hooks/scripts/check.sh" in rendered["hooks"]["PreToolUse"][0]["command"]


def test_canvas_snapshot_preserves_tree_bytes_and_modes(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    bundle = tmp_path / "diagram"
    nested = bundle / "bin/run"
    nested.parent.mkdir(parents=True)
    nested.write_bytes(b"\x00\xff")
    nested.chmod(0o755)
    preimage, candidate = service._candidate(
        service._Root("copilot-config", "copilot", tmp_path),
        bundle,
        "package",
        "diagram",
        {"import_layout": "canvas"},
    )
    candidate["content_fingerprint"] = preimage["content_fingerprint"]

    package = service._snapshot(candidate, _item("bin/run"), bundle, preimage, "op")
    copied = package / ".apm/extensions/diagram/bin/run"

    assert copied.read_bytes() == b"\x00\xff"
    if os.name != "nt":
        assert stat.S_IMODE(copied.stat().st_mode) & 0o111


def test_plugin_fanin_preserves_union_provenance_and_marketplace(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    (plugin / "plugin.json").write_text("{}")
    activation = tmp_path / "installed.json"
    activation.write_text("{}")
    marketplace = tmp_path / "marketplaces.json"
    marketplace.write_text("{}")
    discovered = PluginDiscovery(
        (
            PluginImport(
                "demo",
                plugin,
                ("claude", "codex"),
                "git",
                {"source": "https://example.invalid/demo.git", "ref": "a" * 40},
                (activation,),
            ),
        ),
        (
            MarketplaceImport(
                "market",
                marketplace,
                "claude",
                {
                    "source": {
                        "url": "https://example.invalid/market.git",
                        "ref": "v1",
                        "path": "catalog/marketplace.json",
                        "install_path": "/cache/market",
                    }
                },
            ),
        ),
    )
    monkeypatch.setattr(service, "discover_plugin_state", lambda _roots: discovered)

    candidates, _ = service._discover_plugins(["claude", "codex"])
    imported = next(item for item in candidates if item["kind"] == "plugin")
    registry_item = next(item for item in candidates if item["kind"] == "marketplace")
    service._register_marketplace(registry_item["name"], registry_item["payload"])

    assert imported["source_target"] == ["claude", "codex"]
    assert imported["provenance"] == "git"
    registered = json.loads((home / ".apm/marketplaces.json").read_text())["marketplaces"][0]
    assert registered["ref"] == "v1"
    assert registered["path"] == "catalog/marketplace.json"
    assert registered["install_path"] == "/cache/market"


def test_mcp_manifest_keeps_dependency_targets_and_no_empty_install_fallback(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    path = service._update_manifest(
        [],
        [
            {
                "name": "idea",
                "registry": False,
                "transport": "http",
                "url": "https://example.invalid/mcp",
                "targets": ["intellij"],
            }
        ],
    )
    calls = []
    monkeypatch.setattr(
        service, "_install_manifest", lambda manifest, targets: calls.append(targets)
    )

    targets = sorted(
        set() & (set(service.KNOWN_TARGETS) | set(service.ClientFactory.supported_clients()))
    )
    if targets:
        service._install_manifest(path, targets)

    manifest = yaml.safe_load((home / ".apm/apm.yml").read_text())
    assert manifest["dependencies"]["mcp"][0]["targets"] == ["intellij"]
    assert calls == []


def test_activation_failure_recovery_restores_exact_bytes_and_mode(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    activation = tmp_path / "installed_plugins.json"
    original = json.dumps({"plugins": {"demo": [{"installPath": str(plugin)}]}}).encode()
    activation.write_bytes(original)
    activation.chmod(0o640)
    candidate = {
        "source_target": ["claude", "codex"],
        "payload": {"activation_paths": [str(activation)]},
    }
    journal = {"operation_id": "a" * 32, "retired_activations": []}

    service._capture_plugin_activation(candidate, plugin, journal)
    service._retire_plugin_activation(candidate, plugin, journal)
    service._restore_retired_activations(journal)

    assert activation.read_bytes() == original
    if os.name != "nt":
        assert stat.S_IMODE(activation.stat().st_mode) == 0o640


def test_intellij_mcp_only_apply_has_no_fallback_target(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    config_root = tmp_path / "config"
    monkeypatch.setenv("LOCALAPPDATA" if os.name == "nt" else "XDG_CONFIG_HOME", str(config_root))
    monkeypatch.setenv("APM_E2E_TESTS", "1")
    config = config_root / "github-copilot/intellij/mcp.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps({"servers": {"idea": {"type": "local", "command": "uvx", "args": ["demo"]}}})
    )
    candidates = tmp_path / "protocol/candidates.json"
    plan = tmp_path / "protocol/plan.json"

    service.ImportService().scan(
        sources=("intellij",),
        candidate_file=candidates,
        plan_json=plan,
        coordinator="standalone",
    )
    result = service.ImportService().apply(
        candidate_file=candidates,
        plan_file=plan,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )

    assert result["state"] == "complete"
    assert "idea" in json.loads(config.read_text())["servers"]
    assert not (home / ".claude").exists()
    assert not (home / ".codex").exists()
    second = service.ImportService().scan(
        sources=("intellij",),
        candidate_file=tmp_path / "protocol/second.json",
        plan_json=None,
        coordinator="standalone",
    )
    assert not [
        item
        for item in second["items"]
        if item["classification"] in {"importable", "local-package"}
    ]


def test_canvas_apply_and_second_scan_has_no_work(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    monkeypatch.setenv("APM_E2E_TESTS", "1")
    canvas = home / ".copilot/extensions/diagram"
    canvas.mkdir(parents=True)
    (canvas / "extension.mjs").write_text("export default {}\n", encoding="utf-8")
    candidates = tmp_path / "protocol/candidates.json"
    plan = tmp_path / "protocol/plan.json"

    service.ImportService().scan(
        sources=("copilot",),
        candidate_file=candidates,
        plan_json=plan,
        coordinator="standalone",
    )
    result = service.ImportService().apply(
        candidate_file=candidates,
        plan_file=plan,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )
    assert result["state"] == "complete"

    second = service.ImportService().scan(
        sources=("copilot",),
        candidate_file=tmp_path / "protocol/second.json",
        plan_json=None,
        coordinator="standalone",
    )
    assert not [
        item
        for item in second["items"]
        if item["classification"] in {"importable", "local-package"}
    ]
