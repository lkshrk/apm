from __future__ import annotations

import json
from dataclasses import replace

import pytest

from apm_cli.factory import ClientFactory
from apm_cli.importing.discovery import (
    NativeResource,
    discover_filesystem_resources,
    user_scope_mappings,
    validate_import_strategies,
)
from apm_cli.importing.mcp_discovery import (
    MCPSource,
    discover_mcp_sources,
    validate_mcp_import_coverage,
)
from apm_cli.importing.service import ImportService
from apm_cli.integration.targets import KNOWN_TARGETS, PrimitiveMapping


def test_registry_discovery_aggregates_shared_physical_skills(tmp_path, monkeypatch):
    monkeypatch.delenv("CODEX_HOME", raising=False)
    skill = tmp_path / ".agents" / "skills" / "shared" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# shared\n", encoding="utf-8")
    agent = tmp_path / ".codex" / "agents" / "reviewer.toml"
    agent.parent.mkdir(parents=True)
    agent.write_text('name = "reviewer"\n', encoding="utf-8")

    found = discover_filesystem_resources(("agent-skills", "codex"), home=tmp_path)

    shared = next(item for item in found if item.name == "shared")
    assert shared.path == skill.parent.resolve()
    assert shared.targets == ("agent-skills", "codex")
    assert {(item.kind, item.name) for item in found} >= {("agent", "reviewer")}


def test_discovery_exposes_presence_and_custom_hooks(tmp_path):
    marker = tmp_path / "custom.txt"
    marker.write_text("custom\n", encoding="utf-8")

    def custom(target, profile, root):
        del profile, root
        yield NativeResource(tmp_path, marker, "skill", "custom", (target,), "custom")

    assert (
        discover_filesystem_resources(
            ("hermes",),
            home=tmp_path,
            presence_hook=lambda target, profile, root: False,
            custom_hook=custom,
        )
        == []
    )
    assert [
        item.name
        for item in discover_filesystem_resources(("hermes",), home=tmp_path, custom_hook=custom)
    ] == ["custom"]


def test_strategy_ratchet_names_missing_target_and_primitive():
    profile = replace(
        KNOWN_TARGETS["hermes"],
        primitives={"skills": PrimitiveMapping("skills", "/SKILL.md", "skill_standard")},
    )
    with pytest.raises(ValueError, match="synthetic:skills"):
        validate_import_strategies({"synthetic": profile})


def test_current_user_scope_strategy_matrix_is_complete():
    validate_import_strategies()
    expected = {
        "agent-skills": {"skills": "shared"},
        "antigravity": {"skills": "generic"},
        "claude": {
            "instructions": "compiled",
            "agents": "generic",
            "commands": "generic",
            "skills": "generic",
            "hooks": "snapshot",
        },
        "codex": {"agents": "generic", "skills": "shared", "hooks": "snapshot"},
        "copilot": {
            "instructions": "compiled",
            "prompts": "generic",
            "agents": "generic",
            "skills": "shared",
            "hooks": "snapshot",
            "canvas": "custom",
        },
        "copilot-app": {"prompts": "custom"},
        "copilot-cowork": {"skills": "custom"},
        "cursor": {
            "agents": "generic",
            "commands": "generic",
            "skills": "shared",
            "hooks": "snapshot",
        },
        "gemini": {"commands": "generic", "skills": "shared", "hooks": "snapshot"},
        "grok-build": {
            "instructions": "generic",
            "agents": "generic",
            "commands": "generic",
            "skills": "shared",
        },
        "grok-cloud": {"skills": "shared"},
        "hermes": {"skills": "generic"},
        "kiro": {
            "agents": "generic",
            "instructions": "compiled",
            "skills": "generic",
            "hooks": "snapshot",
        },
        "openclaw": {"skills": "generic"},
        "opencode": {"agents": "generic", "commands": "generic", "skills": "shared"},
        "windsurf": {"skills": "shared", "commands": "generic", "hooks": "snapshot"},
    }
    actual = {
        target: {
            kind: mapping.import_strategy for kind, mapping in user_scope_mappings(profile).items()
        }
        for target, profile in KNOWN_TARGETS.items()
        if profile.user_supported
    }
    assert actual == expected


def test_mcp_registry_ratchet_names_new_client(monkeypatch):
    monkeypatch.setattr(
        ClientFactory,
        "supported_clients",
        staticmethod(lambda: frozenset({"covered", "new"})),
    )
    with pytest.raises(ValueError, match="new"):
        validate_mcp_import_coverage({"covered"})


def test_mcp_source_selection_is_factory_driven(tmp_path, monkeypatch):
    config = tmp_path / "mcp.json"
    config.write_text("{}\n", encoding="utf-8")

    class Adapter:
        supports_user_scope = True
        mcp_servers_key = "servers"

        def get_config_path(self):
            return config

        def get_current_config(self):
            return {"servers": {"demo": {"command": "demo"}}}

        def decode_server_config(self, name, native):
            return {"name": name, **native}

    monkeypatch.setattr(
        ClientFactory, "supported_clients", staticmethod(lambda: frozenset({"demo"}))
    )
    monkeypatch.setattr(
        ClientFactory, "create_client", staticmethod(lambda *args, **kwargs: Adapter())
    )

    sources = discover_mcp_sources()

    assert [(source.client, sorted(source.servers)) for source in sources] == [("demo", ["demo"])]
    assert sources[0].servers["demo"]["name"] == "demo"


def test_project_only_mcp_source_requires_explicit_project_root(tmp_path, monkeypatch):
    config = tmp_path / "mcp.json"
    config.write_text("{}\n", encoding="utf-8")

    class Adapter:
        supports_user_scope = False
        mcp_servers_key = "servers"

        def get_config_path(self):
            return config

        def get_current_config(self):
            return {"servers": {"demo": {"command": "demo"}}}

    monkeypatch.setattr(
        ClientFactory, "supported_clients", staticmethod(lambda: frozenset({"project"}))
    )
    monkeypatch.setattr(
        ClientFactory, "create_client", staticmethod(lambda *args, **kwargs: Adapter())
    )

    assert discover_mcp_sources() == []
    assert [source.client for source in discover_mcp_sources(project_root=tmp_path)] == ["project"]


def test_import_service_dispatches_mcp_only_factory_clients(tmp_path, monkeypatch):
    from apm_cli.importing import service

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    config = home / "mcp-only.json"
    config.write_text('{"servers": {}}\n', encoding="utf-8")
    monkeypatch.setattr(
        ClientFactory,
        "supported_clients",
        staticmethod(lambda: frozenset({"mcp-only"})),
    )
    monkeypatch.setattr(
        service,
        "discover_mcp_sources",
        lambda clients, project_root=None: [
            MCPSource("mcp-only", object(), config, {"demo": {"command": "demo"}})
        ],
    )

    candidate_file = tmp_path / "candidates.json"
    ImportService().scan(
        sources=("mcp-only",),
        candidate_file=candidate_file,
        plan_json=None,
        coordinator="standalone",
    )

    candidate = json.loads(candidate_file.read_text(encoding="utf-8"))["candidates"][0]
    assert (candidate["kind"], candidate["source_target"]) == ("mcp", ["mcp-only"])
