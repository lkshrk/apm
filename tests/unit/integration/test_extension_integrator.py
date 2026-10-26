"""Native extensions are generic, resource-preserving executable packages."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from apm_cli.integration.extension_discovery import find_extension_bundles
from apm_cli.integration.extension_integrator import ExtensionIntegrator
from apm_cli.integration.targets import KNOWN_TARGETS


def package(tmp_path, name="arbitrary-tools", namespace="omp", entry="src/factory.ts"):
    root = tmp_path / name
    root.mkdir()
    (root / "package.json").write_text(
        json.dumps({namespace: {"extensions": [entry]}, "type": "module"})
    )
    source = root / entry
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        "export default function(api) { api.registerCommand('local', { handler: async () => {} }); }\n"
    )
    asset = root / "skills" / "using-tools" / "SKILL.md"
    asset.parent.mkdir(parents=True)
    asset.write_text("Runtime resource loaded relative to the package root.\n")
    return root


def install(root, project, **kwargs):
    return ExtensionIntegrator().integrate_extensions_for_target(
        KNOWN_TARGETS["omp"],
        SimpleNamespace(install_path=root),
        project,
        package_name=root.name,
        trust_extensions=True,
        **kwargs,
    )


def test_manifest_package_keeps_resources_and_is_idempotent(tmp_path):
    root = package(tmp_path, namespace="pi", entry=".pi/extensions/comet.ts")
    project = tmp_path / "project"
    result = install(root, project)
    deployed = project / ".omp/extensions/arbitrary-tools"
    assert (deployed / ".pi/extensions/comet.ts").read_bytes() == (
        root / ".pi/extensions/comet.ts"
    ).read_bytes()
    assert (deployed / "skills/using-tools/SKILL.md").is_file()
    assert json.loads((deployed / "package.json").read_text())["omp"]["extensions"] == [
        ".pi/extensions/comet.ts"
    ]
    managed = {path.relative_to(project).as_posix() for path in result.target_paths}
    before = {path: path.stat().st_mtime_ns for path in result.target_paths}
    second = install(root, project, managed_files=managed)
    assert second.files_adopted == 1
    assert {path: path.stat().st_mtime_ns for path in second.target_paths} == before
    assert not (project / ".omp/config.yml").exists()
    assert not (project / ".omp/AGENTS.md").exists()


def test_update_removes_obsolete_owned_assets_and_uninstall_cleans_bundle(tmp_path):
    root = package(tmp_path)
    project = tmp_path / "project"
    first = install(root, project)
    managed = {path.relative_to(project).as_posix() for path in first.target_paths}
    (root / "skills/using-tools/SKILL.md").unlink()
    (root / "src/factory.ts").write_text(
        "export default function(api) { api.registerFlag('arbitrary', {}); }\n"
    )
    updated = install(root, project, managed_files=managed)
    assert not (project / ".omp/extensions/arbitrary-tools/skills/using-tools/SKILL.md").exists()
    managed = {path.relative_to(project).as_posix() for path in updated.target_paths}
    stats = ExtensionIntegrator().sync_for_target(KNOWN_TARGETS["omp"], None, project, managed)
    assert stats["files_removed"] == len(managed)
    assert not (project / ".omp/extensions/arbitrary-tools").exists()


@pytest.mark.parametrize("mutation", ["modified", "foreign"])
def test_update_and_uninstall_preserve_modified_or_foreign_bundle(tmp_path, mutation):
    root = package(tmp_path)
    project = tmp_path / "project"
    result = install(root, project)
    managed = {path.relative_to(project).as_posix() for path in result.target_paths}
    target = project / ".omp/extensions/arbitrary-tools"
    path = target / ("src/factory.ts" if mutation == "modified" else "foreign.txt")
    path.write_text("operator content")
    with pytest.raises(ValueError, match="foreign or modified"):
        install(root, project, managed_files=managed, force=True)
    stats = ExtensionIntegrator().sync_for_target(KNOWN_TARGETS["omp"], None, project, managed)
    assert stats["errors"] == 1
    assert path.read_text() == "operator content"


def test_missing_context_mode_style_build_never_falls_back(tmp_path):
    root = tmp_path / "context-mode"
    root.mkdir()
    (root / "package.json").write_text(
        json.dumps(
            {
                "omp": {"extensions": ["build/adapters/omp/plugin.js"]},
                "pi": {"extensions": ["index.ts"]},
            }
        )
    )
    (root / "index.ts").write_text("export default () => {};\n")
    project = tmp_path / "project"
    with pytest.raises(ValueError, match="does not run npm installs or builds"):
        install(root, project)
    assert not project.exists()
    # The same source is inert on non-omp targets, including an absent build.
    result = ExtensionIntegrator().integrate_extensions_for_target(
        KNOWN_TARGETS["claude"], SimpleNamespace(install_path=root), project, trust_extensions=True
    )
    assert result.target_paths == []
    assert not project.exists()


@pytest.mark.parametrize("entry", ["../escape.ts", "/tmp/escape.ts", "C:\\escape.ts"])
def test_unsafe_manifest_entries_fail_before_destination_creation(tmp_path, entry):
    root = tmp_path / "untrusted-layout"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({"omp": {"extensions": [entry]}}))
    project = tmp_path / "project"
    with pytest.raises(ValueError, match="Unsafe native"):
        install(root, project)
    assert not project.exists()


def test_only_designated_extension_directories_opt_in(tmp_path):
    root = tmp_path / "plain-javascript"
    root.mkdir()
    (root / "index.js").write_text("export default () => {};\n")
    assert find_extension_bundles(root) == []
    native = root / ".omp/extensions/nested"
    native.mkdir(parents=True)
    (native / "index.ts").write_text("export default () => {};\n")
    (root / "asset.txt").write_text("sibling resource")
    result = install(root, tmp_path / "project")
    assert result.files_integrated == 1
    deployed = tmp_path / "project/.omp/extensions/plain-javascript"
    assert (deployed / "asset.txt").read_text() == "sibling resource"
    assert json.loads((deployed / "package.json").read_text())["omp"]["extensions"] == [
        ".omp/extensions/nested/index.ts"
    ]


def test_native_factory_name_collision_is_not_silently_shadowed(tmp_path):
    first = package(tmp_path, name="comet", entry="src/same.ts")
    second = package(tmp_path, name="nebula", entry="src/same.ts")
    project = tmp_path / "project"
    install(first, project)
    with pytest.raises(ValueError, match="name collision"):
        install(second, project)
    assert not (project / ".omp/extensions/nebula").exists()


def test_dependencies_require_extension_trust_not_canvas_trust(tmp_path):
    root = package(tmp_path)
    project = tmp_path / "project"
    result = ExtensionIntegrator().integrate_extensions_for_target(
        KNOWN_TARGETS["omp"], SimpleNamespace(install_path=root), project
    )
    assert result.target_paths == []
    assert not project.exists()


def test_scope_roots_and_environment_leave_skills_shared(tmp_path, monkeypatch):
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(tmp_path / "native-agent"))
    project_target = KNOWN_TARGETS["omp"]
    user_target = project_target.for_scope(user_scope=True)
    assert project_target.root_dir == ".omp"
    assert Path(user_target.root_dir) == tmp_path / "native-agent"
    assert project_target.skills_rel_root == user_target.skills_rel_root == ".agents/skills"
    assert project_target.compile_family is None


def test_receipt_edits_cannot_reauthorize_modified_payload(tmp_path):
    from apm_cli.utils.content_hash import compute_file_hash

    root = package(tmp_path)
    project = tmp_path / "project"
    first = install(root, project)
    managed = {path.relative_to(project).as_posix() for path in first.target_paths}
    hashes = {
        path.relative_to(project).as_posix(): compute_file_hash(path) for path in first.target_paths
    }
    receipt = project / ".omp/extensions/arbitrary-tools/.apm-extension.json"
    receipt.write_text(receipt.read_text() + " ")
    with pytest.raises(ValueError, match="foreign or modified"):
        install(root, project, managed_files=managed, managed_file_hashes=hashes)
    result = ExtensionIntegrator().sync_for_target(
        KNOWN_TARGETS["omp"], None, project, managed, managed_file_hashes=hashes
    )
    assert result["errors"] == 1
    assert receipt.exists()


def test_custom_agent_directory_outside_home_roundtrips(tmp_path, monkeypatch):
    from apm_cli.core.scope import InstallScope

    home = tmp_path / "home"
    home.mkdir()
    agent_dir = tmp_path / "external-profile"
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(agent_dir))
    root = package(tmp_path)
    target = KNOWN_TARGETS["omp"].for_scope(user_scope=True)
    result = ExtensionIntegrator().integrate_extensions_for_target(
        target,
        SimpleNamespace(install_path=root),
        home,
        scope=InstallScope.USER,
        trust_extensions=True,
        package_name=root.name,
    )
    assert (agent_dir / "extensions/arbitrary-tools/src/factory.ts").is_file()
    managed = {path.as_posix() for path in result.target_paths}
    removed = ExtensionIntegrator().sync_for_target(target, None, home, managed)
    assert removed["files_removed"] == len(managed)


@pytest.mark.parametrize("name", ["apm-hooks-project", "apm-hooks-user"])
def test_generated_bridge_namespace_is_reserved_before_writes(tmp_path, name):
    root = package(tmp_path, name=name)
    project = tmp_path / "project"
    with pytest.raises(ValueError, match="reserved"):
        install(root, project)
    assert not project.exists()


@pytest.mark.parametrize("identity", ["host:8443/org/repo", "@registry/package", "../local-source"])
def test_arbitrary_dependency_keys_have_safe_stable_directory_names(tmp_path, identity):
    root = package(tmp_path)
    project = tmp_path / "project"
    integrator = ExtensionIntegrator()
    first = integrator.integrate_extensions_for_target(
        KNOWN_TARGETS["omp"],
        SimpleNamespace(install_path=root),
        project,
        trust_extensions=True,
        package_name=identity,
    )
    managed = {path.relative_to(project).as_posix() for path in first.target_paths}
    second = integrator.integrate_extensions_for_target(
        KNOWN_TARGETS["omp"],
        SimpleNamespace(install_path=root),
        project,
        trust_extensions=True,
        package_name=identity,
        managed_files=managed,
    )
    assert second.files_adopted == 1
    assert second.target_paths == first.target_paths


def test_linked_resource_and_destination_fail_before_writes(tmp_path):
    root = package(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("never copy this external resource")
    (root / "linked.txt").symlink_to(outside)
    project = tmp_path / "project"
    with pytest.raises(ValueError, match="symlinks"):
        install(root, project)
    assert not project.exists()
    (root / "linked.txt").unlink()
    project.mkdir()
    foreign_root = tmp_path / "foreign-root"
    foreign_root.mkdir()
    (project / ".omp").symlink_to(foreign_root, target_is_directory=True)
    with pytest.raises(ValueError, match="Symlinked native extension destination"):
        install(root, project)
    assert list(foreign_root.iterdir()) == []


def test_nested_missing_manifest_can_be_recognized_without_activation(tmp_path):
    root = tmp_path / "mixed-package"
    native = root / ".omp/extensions/adapter"
    native.mkdir(parents=True)
    (native / "package.json").write_text(json.dumps({"omp": {"extensions": ["build/missing.js"]}}))
    declared = find_extension_bundles(root, validate_entries=False)
    assert declared[0].entries == (".omp/extensions/adapter/build/missing.js",)
    with pytest.raises(ValueError, match="Missing or unsupported"):
        find_extension_bundles(root)


@pytest.mark.parametrize("name", ["apm-hooks-project", "apm-hooks-user"])
@pytest.mark.parametrize("suffix", [".ts", ".js", ".mjs", ".cjs"])
def test_declared_native_factory_cannot_shadow_scoped_hook_runtime(tmp_path, name, suffix):
    root = package(tmp_path, name="unrelated-package", entry=f"src/{name}{suffix}")
    project = tmp_path / "project"
    with pytest.raises(ValueError, match="reserved"):
        install(root, project)
    assert not project.exists()


def test_external_user_native_paths_keep_target_and_scope_in_ledger(tmp_path, monkeypatch):
    from apm_cli.core.scope import InstallScope
    from apm_cli.install.manifest_reconcile import union_preserving
    from apm_cli.utils.content_hash import compute_file_hash

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(tmp_path / "outside-agent"))
    target = KNOWN_TARGETS["omp"].for_scope(user_scope=True)
    root = package(tmp_path)
    result = ExtensionIntegrator().integrate_extensions_for_target(
        target,
        SimpleNamespace(install_path=root),
        home,
        scope=InstallScope.USER,
        trust_extensions=True,
        package_name=root.name,
    )
    paths = [path.as_posix() for path in result.target_paths]
    hashes = {path.as_posix(): compute_file_hash(path) for path in result.target_paths}
    _, _, ledger = union_preserving(
        paths,
        hashes,
        [],
        {},
        [target],
        [target],
        owner="arbitrary-tools",
        include_ledger=True,
        user_scope=True,
        project_root=home,
    )
    assert len(ledger.records) == len(paths)
    assert {
        (record.locator.target, record.locator.scope) for record in ledger.records.values()
    } == {("omp", "user")}
    assert {record.locator.value for record in ledger.records.values()} == set(paths)


def test_native_omp_namespace_is_authoritative_over_pi_fields(tmp_path):
    root = package(tmp_path, namespace="pi")
    manifest = json.loads((root / "package.json").read_text())
    manifest["omp"] = {"tools": []}
    (root / "package.json").write_text(json.dumps(manifest))
    assert find_extension_bundles(root) == []


def test_first_party_native_install_is_bounded_and_repeatable(tmp_path):
    project = tmp_path / "workspace"
    authored = project / ".apm/extensions/tool"
    authored.mkdir(parents=True)
    (authored / "index.ts").write_text("export default () => {};\n")
    (authored / "asset.txt").write_text("bounded resource")
    (project / ".env").write_text("PRIVATE_PROJECT_SECRET=never-copy\n")
    ambient = project / ".omp/extensions"
    ambient.mkdir(parents=True)
    (ambient / "ambient.ts").write_text("export default () => {};\n")
    bridge = ambient / "apm-hooks-project/index.ts"
    bridge.parent.mkdir()
    bridge.write_text("export default () => {};\n")
    tools = project / "node_modules/.bin"
    tools.mkdir(parents=True)
    (tools / "external-tool").symlink_to(tmp_path / "unrelated-missing-executable")
    info = SimpleNamespace(install_path=project)
    integrator = ExtensionIntegrator()
    first = integrator.integrate_extensions_for_target(
        KNOWN_TARGETS["omp"], info, project, is_first_party=True, package_name="_local"
    )
    destination = ambient / "_local"
    assert (destination / "tool/asset.txt").read_text() == "bounded resource"
    assert not (destination / ".env").exists()
    assert not (destination / ".omp").exists()
    assert not (destination / "node_modules").exists()
    assert (ambient / "ambient.ts").read_text() == "export default () => {};\n"
    managed = {path.relative_to(project).as_posix() for path in first.target_paths}
    second = integrator.integrate_extensions_for_target(
        KNOWN_TARGETS["omp"],
        info,
        project,
        is_first_party=True,
        package_name="_local",
        managed_files=managed,
    )
    assert second.files_adopted == 1
    assert second.target_paths == first.target_paths
    removed = integrator.sync_for_target(KNOWN_TARGETS["omp"], None, project, managed)
    assert removed["files_removed"] == len(managed)
    assert not destination.exists()
    assert bridge.exists()
    assert (ambient / "ambient.ts").exists()


def test_first_party_root_native_manifest_is_rejected_before_copying_project(tmp_path):
    project = package(tmp_path, name="workspace")
    (project / ".env").write_text("PRIVATE_PROJECT_SECRET=never-copy\n")
    with pytest.raises(ValueError, match=r"whole project.*private files"):
        ExtensionIntegrator().integrate_extensions_for_target(
            KNOWN_TARGETS["omp"],
            SimpleNamespace(install_path=project),
            project,
            is_first_party=True,
            package_name="_local",
        )
    assert not (project / ".omp").exists()


def test_null_omp_namespace_deploys_pi_declared_native_entry(tmp_path):
    root = package(tmp_path, namespace="pi")
    manifest = json.loads((root / "package.json").read_text())
    manifest["omp"] = None
    (root / "package.json").write_text(json.dumps(manifest))
    project = tmp_path / "project"
    result = install(root, project)
    assert result.files_integrated == 1
    deployed = json.loads((project / ".omp/extensions/arbitrary-tools/package.json").read_text())
    assert deployed["omp"]["extensions"] == ["src/factory.ts"]
