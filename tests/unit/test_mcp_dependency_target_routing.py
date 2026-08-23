from __future__ import annotations

import json

from apm_cli.core.scope import InstallScope
from apm_cli.core.target_detection import EffectiveTargetDecision
from apm_cli.importing import service as importing
from apm_cli.integration.mcp_integrator import MCPIntegrator
from apm_cli.integration.mcp_integrator_install import _dependency_target_runtimes
from apm_cli.models.dependency.mcp import MCPDependency


def _dep(name: str, targets: list[str] | None = None) -> MCPDependency:
    raw = {
        "name": name,
        "registry": False,
        "transport": "stdio",
        "command": "demo",
    }
    if targets is not None:
        raw["targets"] = targets
    return MCPDependency.from_dict(raw)


def _install(monkeypatch, tmp_path, deps, selected, installed=None, managed=None):
    installed = installed if installed is not None else set()
    managed = managed if managed is not None else {}
    calls = []
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr("apm_cli.integration.mcp_integrator._get_console", lambda: None)

    def missing(names, runtimes, **_kwargs):
        return [
            name for name in names if any((runtime, name) not in installed for runtime in runtimes)
        ]

    def write(runtime, names, *_args, **_kwargs):
        calls.extend((runtime, name) for name in names)
        installed.update((runtime, name) for name in names)
        return True

    monkeypatch.setattr(MCPIntegrator, "_check_self_defined_servers_needing_installation", missing)
    monkeypatch.setattr(MCPIntegrator, "_install_for_runtime", write)
    count = MCPIntegrator.install(
        deps,
        explicit_target=selected,
        target_decision=EffectiveTargetDecision(selected, "import review"),
        project_root=tmp_path,
        user_scope=True,
        scope=InstallScope.USER,
        managed_target_servers=managed,
    )
    return count, calls, installed, managed


def test_vscode_only_dependency_does_not_broaden_to_copilot(monkeypatch, tmp_path):
    count, calls, _, managed = _install(
        monkeypatch,
        tmp_path,
        [_dep("editor", ["vscode"])],
        ["vscode"],
    )

    assert count == 1
    assert calls == [("vscode", "editor")]
    assert managed == {"vscode": {"editor"}}


def test_intellij_only_dependency_stays_intellij(monkeypatch, tmp_path):
    _, calls, _, managed = _install(
        monkeypatch,
        tmp_path,
        [_dep("idea", ["intellij"])],
        ["intellij"],
    )

    assert calls == [("intellij", "idea")]
    assert managed == {"intellij": {"idea"}}


def test_multiple_dependencies_keep_independent_target_sets(monkeypatch, tmp_path):
    _, calls, _, managed = _install(
        monkeypatch,
        tmp_path,
        [
            _dep("editor", ["vscode"]),
            _dep("idea", ["intellij"]),
            _dep("shared", ["vscode", "intellij"]),
        ],
        ["vscode", "intellij"],
    )

    assert set(calls) == {
        ("vscode", "editor"),
        ("intellij", "idea"),
        ("vscode", "shared"),
        ("intellij", "shared"),
    }
    assert managed == {
        "vscode": {"editor", "shared"},
        "intellij": {"idea", "shared"},
    }


def test_missing_dependency_targets_preserves_existing_broad_install(monkeypatch, tmp_path):
    _, calls, _, managed = _install(
        monkeypatch,
        tmp_path,
        [_dep("legacy")],
        ["copilot", "intellij"],
    )

    assert calls == [("copilot", "legacy"), ("intellij", "legacy")]
    assert managed == {"copilot": {"legacy"}, "intellij": {"legacy"}}


def test_registry_dependencies_use_the_same_target_filter(monkeypatch, tmp_path):
    class Operations:
        def __init__(self, registry_url=None):
            self.registry_url = registry_url

        def validate_servers_exist(self, names):
            return names, []

        def check_servers_needing_installation(self, _targets, names, **_kwargs):
            return names

        def batch_fetch_server_info(self, names):
            return {name: {"name": name} for name in names}

        def collect_environment_variables(self, *_args):
            return {}

        def collect_runtime_variables(self, *_args):
            return {}

    monkeypatch.setattr("apm_cli.registry.operations.MCPServerOperations", Operations)
    targeted = MCPDependency.from_dict({"name": "editor", "targets": ["vscode"]})
    legacy = MCPDependency.from_dict({"name": "legacy"})

    _, calls, _, managed = _install(
        monkeypatch,
        tmp_path,
        [targeted, legacy],
        ["vscode", "intellij"],
    )

    assert set(calls) == {
        ("vscode", "editor"),
        ("copilot", "legacy"),
        ("intellij", "legacy"),
    }
    assert managed == {
        "vscode": {"editor"},
        "copilot": {"legacy"},
        "intellij": {"legacy"},
    }


def test_registry_drives_new_dependency_targets(monkeypatch):
    monkeypatch.setattr(
        "apm_cli.factory.ClientFactory.supported_clients",
        staticmethod(lambda: frozenset({"future"})),
    )

    assert _dependency_target_runtimes(_dep("next", ["future"]), [], ("future",)) == ["future"]


def test_malformed_or_unknown_dependency_targets_fail_closed():
    malformed = _dep("bad")
    malformed.extra = {"targets": "vscode"}

    assert _dependency_target_runtimes(malformed, ["copilot", "vscode"]) == []
    assert _dependency_target_runtimes(_dep("unknown", ["not-a-client"]), ["copilot"]) == []


def test_repeat_install_is_noop_and_keeps_exact_audit_ownership(monkeypatch, tmp_path):
    deps = [_dep("editor", ["vscode"]), _dep("idea", ["intellij"])]
    first_count, first_calls, installed, managed = _install(
        monkeypatch,
        tmp_path,
        deps,
        ["vscode", "intellij"],
    )
    second_count, second_calls, _, second_managed = _install(
        monkeypatch,
        tmp_path,
        deps,
        ["vscode", "intellij"],
        installed,
        managed,
    )

    assert first_count == 2
    assert set(first_calls) == {("vscode", "editor"), ("intellij", "idea")}
    assert second_count == 0
    assert second_calls == []
    assert second_managed == {"vscode": {"editor"}, "intellij": {"idea"}}


def test_targets_control_metadata_is_not_rendered_as_native_extra():
    info = MCPIntegrator._build_self_defined_info(
        MCPDependency.from_dict(
            {
                "name": "editor",
                "registry": False,
                "transport": "stdio",
                "command": "demo",
                "targets": ["vscode"],
                "oauth": True,
            }
        )
    )

    assert info["_extra"] == {"oauth": True}


def test_vscode_import_audits_without_copilot_broadening_and_second_scan_is_managed(
    monkeypatch, tmp_path
):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    workspace = tmp_path / "workspace"
    config = workspace / ".vscode/mcp.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps({"servers": {"editor": {"type": "stdio", "command": "demo"}}}),
        encoding="utf-8",
    )
    candidates = tmp_path / "candidates.json"
    plan = tmp_path / "plan.json"
    first = importing.ImportService().scan(
        sources=("vscode",),
        candidate_file=candidates,
        plan_json=plan,
        coordinator="standalone",
        project_root=workspace,
    )
    assert any(item["kind"] == "mcp" for item in first["items"])
    audited = []
    real_audit = importing._audit_import

    def record_audit(path):
        real_audit(path)
        audited.append(path)

    monkeypatch.setattr(importing, "_audit_import", record_audit)
    result = importing.ImportService().apply(
        candidate_file=candidates,
        plan_file=plan,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )

    assert result["state"] == "complete"
    assert audited == [workspace / "apm.yml"]
    assert not (home / ".copilot/mcp-config.json").exists()
    deployed = workspace / ".vscode/mcp.json"
    assert "editor" in json.loads(deployed.read_text(encoding="utf-8"))["servers"]
    second = importing.ImportService().scan(
        sources=("vscode",),
        candidate_file=tmp_path / "second.json",
        plan_json=None,
        coordinator="standalone",
        project_root=workspace,
    )
    rescanned = [item for item in second["items"] if item["kind"] == "mcp"]
    assert [(item["classification"], item["proposed_targets"]) for item in rescanned] == [
        ("already-managed", ["vscode"])
    ]
