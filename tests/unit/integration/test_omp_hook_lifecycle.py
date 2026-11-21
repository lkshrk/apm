"""Behavioral coverage for portable omp hooks and shared runtime ownership."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from apm_cli.hook_contract import HookContractError
from apm_cli.integration.hook_integrator import HookIntegrator, native_hook_config
from apm_cli.integration.hook_native_formats import inspect_native_hooks
from apm_cli.integration.omp_hook_integrator import (
    OMP_HOOK_BRIDGES,
    OMP_HOOK_RUNTIME_STATE,
    clean_omp_hooks,
    omp_hook_bridge_path,
)
from apm_cli.integration.targets import KNOWN_TARGETS
from apm_cli.models.apm_package import APMPackage, PackageInfo


def package(
    tmp_path: Path,
    name: str = "portable-kit",
    *,
    event: str = "PreToolUse",
    handler: dict | None = None,
    matcher: str | None = None,
) -> PackageInfo:
    root = tmp_path / "apm_modules" / name
    source = root / "hooks" / "hooks.json"
    source.parent.mkdir(parents=True)
    entry = {"hooks": [handler or {"type": "command", "command": "printf hook"}]}
    if matcher is not None:
        entry["matcher"] = matcher
    source.write_text(json.dumps({"hooks": {event: [entry]}}), encoding="utf-8")
    return PackageInfo(package=APMPackage(name=name, version="1.0.0"), install_path=root)


def install(info: PackageInfo, root: Path, **kwargs):
    return HookIntegrator().integrate_hooks_for_target(KNOWN_TARGETS["omp"], info, root, **kwargs)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_native_artifact_tree_uses_complete_verified_package_context(tmp_path):
    info = package(
        tmp_path,
        handler={
            "type": "command",
            "command": 'node "${CLAUDE_PLUGIN_ROOT}/scripts/check.js"',
            "timeout": 2,
            "env": {"EXAMPLE": "value"},
            "statusMessage": "Inspecting",
        },
        matcher="Bash|Read",
    )
    scripts = info.install_path / "scripts"
    scripts.mkdir()
    (scripts / "check.js").write_text("import '../lib/value.js';", encoding="utf-8")
    (info.install_path / "lib").mkdir()
    (info.install_path / "lib/value.js").write_text("export const value = 1;", encoding="utf-8")
    (info.install_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    selection = HookIntegrator.select_deployable_hook_sources(info.install_path, ["omp"])
    assert info.install_path / "lib/value.js" in selection.bundle_for("omp")
    assert info.install_path / "package.json" in selection.bundle_for("omp")
    result = install(info, tmp_path, source_plan=SimpleNamespace(hook_source_selection=selection))
    native = read_json(tmp_path / ".omp/hooks.json")
    handler = native["hooks"]["PreToolUse"][0]["hooks"][0]
    assert handler["apm"]["root"] == str(info.install_path.resolve())
    assert Path(handler["apm"]["root"], "lib/value.js").is_file()
    assert Path(handler["apm"]["dataDir"]).parent == tmp_path / ".omp/hook-data"
    assert handler["statusMessage"] == "Inspecting"
    assert handler["env"] == {"EXAMPLE": "value"}
    assert "${CLAUDE_PLUGIN_ROOT}" in handler["command"]
    assert set(tree_bytes(tmp_path / ".omp")) == {
        "hooks.json",
        "apm-hooks.json",
        omp_hook_bridge_path(),
        OMP_HOOK_RUNTIME_STATE,
    }
    assert set(result.target_paths) == {
        tmp_path / ".omp" / omp_hook_bridge_path(),
        tmp_path / ".omp" / OMP_HOOK_RUNTIME_STATE,
    }
    assert native_hook_config("omp").nested_handlers is True
    assert not any(
        entry.error for entry in inspect_native_hooks(native, "omp_hooks", nested_handlers=True)
    )


@pytest.mark.parametrize(
    "event,handler,matcher",
    [
        ("PermissionRequest", {"command": "true"}, None),
        ("Notification", {"command": "true"}, None),
        ("SubagentStop", {"command": "true"}, None),
        ("UserPromptSubmit", {"command": "true"}, None),
        ("PreToolUse", {"type": "prompt", "prompt": "permit"}, None),
        ("PreToolUse", {"command": "true", "async": True}, None),
        ("PreToolUse", {"command": "true", "timeout": 30}, None),
        ("SessionEnd", {"command": "true", "timeout": 2}, None),
        ("PreToolUse", {"command": "true", "timeout": True}, None),
        ("Stop", {"command": "true"}, "*"),
        ("PreToolUse", {"command": "true"}, "[invalid"),
        ("PreToolUse", {"command": "true"}, "mcp__server__tool"),
    ],
)
def test_unsupported_semantics_fail_before_any_native_write(tmp_path, event, handler, matcher):
    info = package(tmp_path, event=event, handler=handler, matcher=matcher)
    with pytest.raises(HookContractError):
        install(info, tmp_path)
    assert not (tmp_path / ".omp").exists()


def test_unrelated_native_content_survives_reinstall_and_final_removal(tmp_path):
    info = package(tmp_path)
    target = tmp_path / ".omp"
    target.mkdir()
    foreign = {"hooks": {"ForeignEvent": [{"unrelated": True}]}, "localSetting": 7}
    (target / "hooks.json").write_text(json.dumps(foreign), encoding="utf-8")
    install(info, tmp_path)
    first = tree_bytes(target)
    install(info, tmp_path)
    assert tree_bytes(target) == first
    stats = {"files_removed": 0, "errors": 0}
    clean_omp_hooks(target, stats)
    assert stats["errors"] == 0
    assert read_json(target / "hooks.json") == foreign
    assert not (target / omp_hook_bridge_path()).exists()
    assert not (target / OMP_HOOK_RUNTIME_STATE).exists()
    assert not (target / "apm-hooks.json").exists()


def test_shared_bridge_survives_one_owner_then_disappears_with_last(tmp_path):
    first = package(tmp_path, "first-kit")
    second = package(tmp_path, "second-kit", event="Stop")
    install(first, tmp_path)
    install(second, tmp_path)
    target = tmp_path / ".omp"
    stats = {"files_removed": 0, "errors": 0}
    clean_omp_hooks(target, stats, source_markers=frozenset({"first-kit"}))
    assert (target / omp_hook_bridge_path()).is_file()
    assert set(read_json(target / "hooks.json")["hooks"]) == {"Stop"}
    clean_omp_hooks(target, stats, source_markers=frozenset({"second-kit"}))
    assert stats["errors"] == 0
    assert not (target / "hooks.json").exists()
    assert not (target / "apm-hooks.json").exists()
    assert not (target / omp_hook_bridge_path()).exists()
    assert not (target / OMP_HOOK_RUNTIME_STATE).exists()


@pytest.mark.parametrize("kind", ["foreign", "edited", "symlink"])
def test_bridge_collisions_never_overwrite_native_files(tmp_path, kind):
    info = package(tmp_path)
    target = tmp_path / ".omp"
    bridge = target / omp_hook_bridge_path()
    if kind == "edited":
        install(info, tmp_path)
        bridge.write_text("// user edit", encoding="utf-8")
    else:
        bridge.parent.mkdir(parents=True)
        if kind == "foreign":
            bridge.write_text("export default () => {};", encoding="utf-8")
        else:
            outside = tmp_path / "foreign.ts"
            outside.write_text("foreign", encoding="utf-8")
            bridge.symlink_to(outside)
    before = tree_bytes(target)
    with pytest.raises(HookContractError):
        install(info, tmp_path)
    assert tree_bytes(target) == before


def test_edited_owned_entry_is_not_duplicated_or_deleted(tmp_path):
    info = package(tmp_path)
    install(info, tmp_path)
    target = tmp_path / ".omp"
    path = target / "hooks.json"
    changed = read_json(path)
    changed["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = "printf edited"
    path.write_text(json.dumps(changed), encoding="utf-8")
    before = path.read_bytes()
    with pytest.raises(HookContractError, match="changed or removed"):
        install(info, tmp_path)
    stats = {"files_removed": 0, "errors": 0}
    clean_omp_hooks(target, stats)
    assert stats["errors"] == 1
    assert path.read_bytes() == before
    assert (target / omp_hook_bridge_path()).is_file()


def test_native_manifest_precedence_and_missing_entry_preflight(tmp_path):
    info = package(tmp_path, event="Notification")
    manifest = info.install_path / "package.json"
    manifest.write_text('{"omp":{"extensions":["./dist/main.js"]}}', encoding="utf-8")
    with pytest.raises(ValueError, match="Missing or unsupported"):
        HookIntegrator.select_deployable_hook_sources(info.install_path, ["omp"])
    assert not (tmp_path / ".omp").exists()
    (info.install_path / "dist").mkdir()
    (info.install_path / "dist/main.js").write_text("export default () => {};", encoding="utf-8")
    selection = HookIntegrator.select_deployable_hook_sources(info.install_path, ["omp", "claude"])
    assert not selection.descriptors_for("omp")
    assert selection.descriptors_for("claude")
    source = info.install_path / "hooks/hooks.json"
    source.rename(source.with_name("hooks-omp.json"))
    with pytest.raises(ValueError, match="duplicate activation"):
        HookIntegrator.select_deployable_hook_sources(info.install_path, ["omp"])


def test_excluded_target_does_not_validate_or_activate_native_extensions(tmp_path):
    info = package(tmp_path)
    (info.install_path / "package.json").write_text(
        '{"omp":{"extensions":["missing.js"]}}', encoding="utf-8"
    )
    selection = HookIntegrator.select_deployable_hook_sources(info.install_path, ["claude"])
    assert selection.descriptors_for("claude")
    assert not selection.descriptors_for("omp")


def test_complete_context_is_rechecked_at_write_boundary(tmp_path):
    info = package(tmp_path)
    selection = HookIntegrator.select_deployable_hook_sources(info.install_path, ["omp"])
    (info.install_path / "unexpected-resource.txt").write_text("new content", encoding="utf-8")
    with pytest.raises(HookContractError, match="changed after source authorization"):
        install(info, tmp_path, source_plan=SimpleNamespace(hook_source_selection=selection))
    assert not (tmp_path / ".omp").exists()


def test_symlinked_sibling_context_rejected_before_deployment(tmp_path):
    info = package(tmp_path)
    (info.install_path / "sibling").symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(HookContractError, match="symlink"):
        install(info, tmp_path)
    assert not (tmp_path / ".omp").exists()


def test_dropping_target_removes_owned_bridge_and_descriptor(tmp_path):
    info = package(tmp_path)
    install(info, tmp_path)
    stats = HookIntegrator().reconcile_dropped_targets(tmp_path, {"omp"})
    assert stats["errors"] == 0
    assert not (tmp_path / ".omp" / omp_hook_bridge_path()).exists()
    assert not (tmp_path / ".omp/hooks.json").exists()


def test_user_scope_native_root_override_is_honored(tmp_path, monkeypatch):
    info = package(tmp_path)
    native_root = tmp_path / "custom-agent"
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(native_root))
    target = KNOWN_TARGETS["omp"].for_scope(user_scope=True)
    HookIntegrator().integrate_hooks_for_target(target, info, tmp_path, user_scope=True)
    assert (native_root / omp_hook_bridge_path(user_scope=True)).is_file()
    handler = read_json(native_root / "hooks.json")["hooks"]["PreToolUse"][0]["hooks"][0]
    assert Path(handler["apm"]["dataDir"]).parent == native_root / "hook-data"
    assert not (tmp_path / ".omp/hooks.json").exists()


def test_existing_unowned_runtime_metadata_is_never_activated(tmp_path):
    info = package(tmp_path)
    target = tmp_path / ".omp"
    target.mkdir()
    foreign = {
        "hooks": {
            "Stop": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": "printf foreign",
                            "apm": {
                                "owner": "not-managed",
                                "root": str(tmp_path),
                                "dataDir": str(tmp_path),
                            },
                        }
                    ]
                }
            ]
        }
    }
    (target / "hooks.json").write_text(json.dumps(foreign), encoding="utf-8")
    before = tree_bytes(target)
    with pytest.raises(HookContractError, match="unowned"):
        install(info, tmp_path)
    assert tree_bytes(target) == before


def test_edited_bridge_prevents_destructive_reconciliation(tmp_path):
    info = package(tmp_path)
    install(info, tmp_path)
    target = tmp_path / ".omp"
    (target / omp_hook_bridge_path()).write_text("// user modification", encoding="utf-8")
    before = tree_bytes(target)
    stats = {"files_removed": 0, "errors": 0}
    clean_omp_hooks(target, stats)
    assert stats["errors"] == 1
    assert tree_bytes(target) == before


def test_invalid_later_descriptor_cannot_partially_write(tmp_path):
    info = package(tmp_path)
    (info.install_path / "hooks/z-invalid.json").write_text(
        '{"hooks":{"Notification":[{"command":"true"}]}}',
        encoding="utf-8",
    )
    with pytest.raises(HookContractError, match="Notification"):
        install(info, tmp_path)
    assert not (tmp_path / ".omp").exists()


def test_flat_bash_handler_and_relative_script_use_existing_ir(tmp_path):
    info = package(tmp_path)
    script = info.install_path / "hooks/check.sh"
    script.write_text("printf hook", encoding="utf-8")
    (info.install_path / "hooks/hooks.json").write_text(
        '{"preToolUse":[{"bash":"./check.sh","timeoutSec":1}]}',
        encoding="utf-8",
    )
    install(info, tmp_path)
    handler = read_json(tmp_path / ".omp/hooks.json")["hooks"]["PreToolUse"][0]["hooks"][0]
    assert handler["command"] == str(script.resolve())
    assert handler["shell"] == "bash"
    assert handler["timeout"] == 1


@pytest.mark.parametrize("mode", ["empty", "deleted", "native"])
def test_update_removing_final_hook_removes_owned_runtime(tmp_path, mode):
    info = package(tmp_path)
    install(info, tmp_path)
    source = info.install_path / "hooks/hooks.json"
    if mode == "empty":
        source.write_text('{"hooks":{}}', encoding="utf-8")
    elif mode == "deleted":
        source.unlink()
    else:
        (info.install_path / "package.json").write_text(
            '{"omp":{"extensions":["main.js"]}}',
            encoding="utf-8",
        )
        (info.install_path / "main.js").write_text("export default () => {};", encoding="utf-8")
    result = install(info, tmp_path)
    assert result.files_integrated == 0
    assert not (tmp_path / ".omp/hooks.json").exists()
    assert not (tmp_path / ".omp" / omp_hook_bridge_path()).exists()
    assert not (tmp_path / ".omp" / OMP_HOOK_RUNTIME_STATE).exists()


def test_removed_owner_reconciliation_preserves_surviving_owner(tmp_path):
    first = package(tmp_path, "removed-kit")
    second = package(tmp_path, "surviving-kit", event="Stop")
    install(first, tmp_path)
    install(second, tmp_path)
    stats = HookIntegrator().reconcile_removed_owner_targets(tmp_path, {"removed-kit"})
    assert stats["errors"] == 0
    assert set(read_json(tmp_path / ".omp/hooks.json")["hooks"]) == {"Stop"}
    assert (tmp_path / ".omp" / omp_hook_bridge_path()).is_file()


def test_removed_owner_reconciliation_reaches_recorded_previous_root(tmp_path):
    from dataclasses import replace

    info = package(tmp_path)
    previous_root = tmp_path / "retired-agent-root"
    target = replace(KNOWN_TARGETS["omp"], root_dir=str(previous_root))
    HookIntegrator().integrate_hooks_for_target(target, info, tmp_path)
    stats = HookIntegrator().reconcile_removed_owner_targets(
        tmp_path,
        {"portable-kit"},
        native_roots=[previous_root],
    )
    assert stats["errors"] == 0
    assert not (previous_root / "hooks.json").exists()
    assert not (previous_root / omp_hook_bridge_path()).exists()


def test_removed_owner_does_not_touch_edited_unrelated_owner(tmp_path):
    info = package(tmp_path, "surviving-kit")
    install(info, tmp_path)
    target = tmp_path / ".omp"
    (target / omp_hook_bridge_path()).write_text("// survivor's edit", encoding="utf-8")
    before = tree_bytes(target)
    stats = HookIntegrator().reconcile_removed_owner_targets(tmp_path, {"other-kit"})
    assert stats["errors"] == 0
    assert tree_bytes(target) == before


def test_removed_owner_without_sidecar_proof_reports_failure(tmp_path):
    info = package(tmp_path)
    install(info, tmp_path)
    target = tmp_path / ".omp"
    (target / "apm-hooks.json").unlink()
    before = tree_bytes(target)
    stats = HookIntegrator().reconcile_removed_owner_targets(tmp_path, {"portable-kit"})
    assert stats["errors"] == 1
    assert tree_bytes(target) == before


@pytest.mark.parametrize("user_first", [True, False])
def test_project_and_user_bridges_have_independent_native_names(tmp_path, monkeypatch, user_first):
    from apm_cli.integration.extension_discovery import native_extension_name
    from apm_cli.integration.omp_hook_namespace import native_extension_module_paths

    home = tmp_path / "home"
    project = tmp_path / "workspace"
    home.mkdir()
    project.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.chdir(project)
    user_root = home / ".omp/agent"
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(user_root))
    global_info = package(tmp_path, "global-guard")
    project_info = package(tmp_path, "project-guard")

    def install_user():
        target = KNOWN_TARGETS["omp"].for_scope(user_scope=True)
        HookIntegrator().integrate_hooks_for_target(target, global_info, home, user_scope=True)

    if user_first:
        install_user()
        install(project_info, project)
    else:
        install(project_info, project)
        install_user()
    discovered = [
        *native_extension_module_paths(project / ".omp/extensions"),
        *native_extension_module_paths(user_root / "extensions"),
    ]
    assert {native_extension_name(path) for path in discovered} == {
        "apm-hooks-project",
        "apm-hooks-user",
    }
    assert len(discovered) == 2
    assert (project / ".omp" / OMP_HOOK_BRIDGES["project"]).is_file()
    assert (user_root / OMP_HOOK_BRIDGES["user"]).is_file()
    assert read_json(project / ".omp" / OMP_HOOK_RUNTIME_STATE)["scope"] == "project"
    assert read_json(user_root / OMP_HOOK_RUNTIME_STATE)["scope"] == "user"
    project_handler = read_json(project / ".omp/hooks.json")["hooks"]["PreToolUse"][0]["hooks"][0]
    user_handler = read_json(user_root / "hooks.json")["hooks"]["PreToolUse"][0]["hooks"][0]
    assert project_handler["apm"]["owner"] == "project-guard"
    assert user_handler["apm"]["owner"] == "global-guard"


@pytest.mark.parametrize("scope_name", ["project", "user"])
@pytest.mark.parametrize("suffix", [".ts", ".js"])
def test_loose_native_name_collision_fails_before_hook_writes(tmp_path, scope_name, suffix):
    info = package(tmp_path)
    target = tmp_path / ".omp"
    collision = target / "extensions" / f"apm-hooks-{scope_name}{suffix}"
    collision.parent.mkdir(parents=True)
    collision.write_text("export default () => {};", encoding="utf-8")
    before = tree_bytes(target)
    with pytest.raises(HookContractError, match="collides"):
        install(info, tmp_path)
    assert tree_bytes(target) == before


@pytest.mark.parametrize(
    "declaration", ["apm-hooks-project.mjs", "apm-hooks-project.cjs", "apm-hooks-project"]
)
def test_manifest_native_name_collision_fails_before_hook_writes(tmp_path, declaration):
    info = package(tmp_path)
    target = tmp_path / ".omp"
    foreign = target / "extensions/foreign-package"
    foreign.mkdir(parents=True)
    path = foreign / declaration
    if not path.suffix:
        path.mkdir()
        path /= "index.ts"
    path.write_text("export default () => {};", encoding="utf-8")
    (foreign / "package.json").write_text(
        json.dumps({"omp": {"extensions": [declaration]}}),
        encoding="utf-8",
    )
    before = tree_bytes(target)
    with pytest.raises(HookContractError, match="collides"):
        install(info, tmp_path)
    assert tree_bytes(target) == before


def test_settings_extension_name_collision_is_not_silently_shadowed(tmp_path):
    info = package(tmp_path)
    target = tmp_path / ".omp"
    target.mkdir()
    external = tmp_path / "apm-hooks-project.ts"
    external.write_text("export default () => {};", encoding="utf-8")
    (target / "settings.json").write_text(
        json.dumps({"extensions": [str(external)]}),
        encoding="utf-8",
    )
    before = tree_bytes(target)
    with pytest.raises(HookContractError, match="collides"):
        install(info, tmp_path)
    assert tree_bytes(target) == before


def test_ambiguous_project_ancestor_bridge_is_rejected_before_writes(tmp_path):
    info = package(tmp_path)
    install(info, tmp_path)
    before = tree_bytes(tmp_path / ".omp")
    nested = tmp_path / "nested-project"
    nested.mkdir()
    with pytest.raises(HookContractError, match="ambiguous omp ancestor"):
        install(info, nested)
    assert not (nested / ".omp").exists()
    assert tree_bytes(tmp_path / ".omp") == before


def test_removing_owner_preserves_edited_siblings_ownership_evidence(tmp_path):
    first = package(tmp_path, "owner-a")
    second = package(tmp_path, "owner-b")
    install(first, tmp_path)
    install(second, tmp_path)
    target = tmp_path / ".omp"
    original_b = next(
        entry
        for entry in read_json(target / "apm-hooks.json")["PreToolUse"]
        if entry["_apm_source"] == "owner-b"
    )
    config = read_json(target / "hooks.json")
    entry_b = next(
        entry
        for entry in config["hooks"]["PreToolUse"]
        if entry["hooks"][0]["apm"]["owner"] == "owner-b"
    )
    entry_b["hooks"][0]["command"] = "printf edited-sibling"
    (target / "hooks.json").write_text(json.dumps(config), encoding="utf-8")
    stats = HookIntegrator().reconcile_removed_owner_targets(tmp_path, {"owner-a"})
    assert stats["errors"] == 0
    assert read_json(target / "apm-hooks.json") == {"PreToolUse": [original_b]}
    before = tree_bytes(target)
    stats = HookIntegrator().reconcile_removed_owner_targets(tmp_path, {"owner-b"})
    assert stats["errors"] == 1
    assert tree_bytes(target) == before


@pytest.mark.parametrize("root_script", [False, True])
def test_first_party_hooks_do_not_rediscover_deployed_content_or_project_secrets(
    tmp_path, root_script
):
    project = tmp_path / "project"
    hooks = project / ".apm/hooks"
    hooks.mkdir(parents=True)
    script = project / "root-hook.sh" if root_script else hooks / "check.sh"
    script.write_text("printf inspected", encoding="utf-8")
    command = 'bash "${PLUGIN_ROOT}/' + script.relative_to(project).as_posix() + '"'
    (hooks / "hooks.json").write_text(
        json.dumps(
            {
                "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": command}]}]},
            }
        ),
        encoding="utf-8",
    )
    secret = project / ".env"
    secret.write_text("DO_NOT_COPY_PROJECT_SECRET", encoding="utf-8")
    ordinary_link = project / "ordinary-project-link"
    ordinary_link.symlink_to(tmp_path, target_is_directory=True)
    ambient = project / ".omp/extensions/ambient/index.ts"
    ambient.parent.mkdir(parents=True)
    ambient.write_text("export default () => {};", encoding="utf-8")
    info = PackageInfo(
        package=APMPackage(name="local-hooks", version="1.0.0"), install_path=project
    )
    for _iteration in range(2):
        selection = HookIntegrator.select_deployable_hook_sources(
            project, ["omp"], is_first_party=True
        )
        assert selection.is_first_party
        assert secret not in selection.files
        assert ordinary_link not in selection.files
        assert ambient not in selection.files
        assert script in selection.files
        result = install(
            info, project, source_plan=SimpleNamespace(hook_source_selection=selection)
        )
        assert result.files_integrated == 1
    assert secret.read_text(encoding="utf-8") == "DO_NOT_COPY_PROJECT_SECRET"
    assert ordinary_link.is_symlink()
    assert ambient.read_text(encoding="utf-8") == "export default () => {};"
    assert all(
        b"DO_NOT_COPY_PROJECT_SECRET" not in value
        for value in tree_bytes(project / ".omp").values()
    )
    handler = read_json(project / ".omp/hooks.json")["hooks"]["PreToolUse"][0]["hooks"][0]
    assert handler["apm"]["root"] == str(project.resolve())
    assert len(read_json(project / ".omp/hooks.json")["hooks"]["PreToolUse"]) == 1


def test_dependency_removal_preserves_first_party_omp_hooks_without_rebuild(tmp_path):
    project = tmp_path / "project"
    hooks = project / ".apm/hooks"
    hooks.mkdir(parents=True)
    (hooks / "hooks.json").write_text(
        '{"hooks":{"PreToolUse":[{"hooks":[{"command":"printf first-party"}]}]}}',
        encoding="utf-8",
    )
    local = PackageInfo(package=APMPackage(name="workspace", version="1.0.0"), install_path=project)
    dependency = package(tmp_path, "removed-dependency")
    install(local, project)
    install(dependency, project)
    target = project / ".omp"
    bridge_before = (target / omp_hook_bridge_path()).read_bytes()
    stats = HookIntegrator().reconcile_removed_owner_targets(project, {"removed-dependency"})
    assert stats["errors"] == 0
    handler = read_json(target / "hooks.json")["hooks"]["PreToolUse"][0]["hooks"][0]
    assert handler["apm"]["owner"] == "_local/workspace"
    assert handler["command"] == "printf first-party"
    survivor_bytes = tree_bytes(target)
    manifest = APMPackage(name="workspace", version="1.0.0", targets=["omp"])
    stats = HookIntegrator().reconcile_after_removal(manifest, project)
    assert stats["errors"] == 0
    assert tree_bytes(target) == survivor_bytes
    assert (target / omp_hook_bridge_path()).read_bytes() == bridge_before


def test_first_party_managed_output_reference_never_adopts_target_tree(tmp_path):
    project = tmp_path / "project"
    hooks = project / ".apm/hooks"
    hooks.mkdir(parents=True)
    script = project / ".omp/scripts/explicit.sh"
    script.parent.mkdir(parents=True)
    script.write_text("printf explicitly-referenced", encoding="utf-8")
    unrelated = script.with_name("unrelated.env")
    unrelated.write_text("PRIVATE_RUNTIME_DATA", encoding="utf-8")
    (hooks / "hooks.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "Stop": [
                        {
                            "hooks": [
                                {
                                    "command": 'bash "${PLUGIN_ROOT}/.omp/scripts/explicit.sh"',
                                }
                            ]
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    selection = HookIntegrator.select_deployable_hook_sources(project, ["omp"], is_first_party=True)
    assert selection.files == frozenset({hooks / "hooks.json", script})
    assert unrelated not in selection.files


def test_survivor_profile_without_hooks_cannot_contract_preserved_omp_entries(tmp_path):
    from dataclasses import replace

    info = package(tmp_path)
    install(info, tmp_path)
    target = KNOWN_TARGETS["omp"]
    survivor_profile = replace(
        target,
        primitives={
            name: mapping for name, mapping in target.primitives.items() if name != "hooks"
        },
    )
    before = tree_bytes(tmp_path / ".omp")
    stats = HookIntegrator().reconcile_package_target_restriction(
        info, tmp_path, [survivor_profile]
    )
    assert stats["errors"] == 0
    assert stats["files_removed"] == 0
    assert tree_bytes(tmp_path / ".omp") == before


def test_user_replay_preflight_checks_resolved_scratch_root_not_live_agent(tmp_path, monkeypatch):
    from dataclasses import replace

    from apm_cli.install.audit_target_roots import replay_target

    home = tmp_path / "home"
    home.mkdir()
    live_root = tmp_path / "live-agent"
    scratch_root = tmp_path / "scratch"
    scratch_root.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(live_root))
    monkeypatch.chdir(home)
    info = package(tmp_path)
    integrator = HookIntegrator()
    live_target = KNOWN_TARGETS["omp"].for_scope(user_scope=True)
    integrator.integrate_hooks_for_target(live_target, info, home, user_scope=True)
    live_bridge = live_root / omp_hook_bridge_path(user_scope=True)
    (live_bridge.parent / "package.json").write_text(
        '{"omp":{"extensions":["shadow.ts"]}}',
        encoding="utf-8",
    )
    (live_bridge.parent / "shadow.ts").write_text("export default () => {};", encoding="utf-8")
    live_before = tree_bytes(live_root)
    selection = integrator.select_deployable_hook_sources(info.install_path, ["omp"])
    plan = SimpleNamespace(hook_source_selection=selection)
    scratch_target = replay_target(live_target)
    scratch_agent = scratch_target.deploy_path(scratch_root)
    assert scratch_agent != live_root
    for omitted_targets in ([], [replace(scratch_target, primitives={})]):
        integrator.preflight_hooks_for_targets(
            info,
            scratch_root,
            plan,
            user_scope=True,
            targets=omitted_targets,
        )

    integrator.preflight_hooks_for_targets(
        info,
        scratch_root,
        plan,
        user_scope=True,
        targets=[scratch_target],
    )
    assert not scratch_agent.exists()
    integrator.integrate_hooks_for_target(
        scratch_target,
        info,
        scratch_root,
        user_scope=True,
        source_plan=plan,
    )
    assert tree_bytes(live_root) == live_before
    second_target = replace(
        scratch_target, root_dir="historical-user-root", resolved_deploy_root=None
    )
    integrator.integrate_hooks_for_target(
        second_target,
        info,
        scratch_root,
        user_scope=True,
        source_plan=plan,
    )
    second_bridge = second_target.deploy_path(scratch_root) / omp_hook_bridge_path(user_scope=True)
    (second_bridge.parent / "foreign.ts").write_text("export default () => {};", encoding="utf-8")
    with pytest.raises(HookContractError, match="unrelated content"):
        integrator.preflight_hooks_for_targets(
            info,
            scratch_root,
            plan,
            user_scope=True,
            targets=[scratch_target, second_target],
        )
    assert tree_bytes(live_root) == live_before
