"""Removed native hook owners remain removable after omp is deselected."""

import json
import shutil

import pytest

from apm_cli.deps.lockfile import LockedDependency, LockFile
from apm_cli.install.removed_hook_ownership import reconcile_removed_native_hook_owners
from apm_cli.integration.cleanup import remove_stale_deployed_files
from apm_cli.integration.hook_integrator import HookIntegrator
from apm_cli.integration.targets import KNOWN_TARGETS
from apm_cli.models.apm_package import APMPackage, DependencyReference, PackageInfo
from apm_cli.utils.content_hash import compute_file_hash
from apm_cli.utils.diagnostics import DiagnosticCollector


def install_owner(root, identity):
    reference = DependencyReference.parse(identity)
    source = reference.get_install_path(root / "apm_modules")
    hook = source / "hooks/hooks.json"
    hook.parent.mkdir(parents=True)
    hook.write_text(
        json.dumps(
            {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "printf owned"}]}]}}
        )
    )
    (source / "apm.yml").write_text(f"name: {source.name}\nversion: 1.0.0\n")
    info = PackageInfo(
        package=APMPackage(name=source.name, version="1.0.0"),
        install_path=source,
        dependency_ref=reference,
    )
    result = HookIntegrator().integrate_hooks_for_target(KNOWN_TARGETS["omp"], info, root)
    paths = [path.relative_to(root).as_posix() for path in result.target_paths]
    locked = LockedDependency(
        repo_url=identity,
        deployed_files=paths,
        deployed_file_hashes={relative: compute_file_hash(root / relative) for relative in paths},
    )
    return source, locked


def test_removed_owner_cleanup_works_without_source_or_selected_omp(tmp_path):
    source, dependency = install_owner(tmp_path, "arbitrary/aurora")
    lock = LockFile(dependencies={dependency.get_unique_key(): dependency})
    (tmp_path / "apm.yml").write_text("name: project\nversion: 1.0.0\ntargets: [claude]\n")
    shutil.rmtree(source)
    result = reconcile_removed_native_hook_owners(lock, {dependency.get_unique_key()}, tmp_path)
    assert result["errors"] == 0
    assert not (tmp_path / ".omp/extensions/apm-hooks-project/index.ts").exists()
    assert not (tmp_path / ".omp/apm-hooks-runtime.json").exists()
    assert not (tmp_path / ".omp/hooks.json").exists()


def test_surviving_and_foreign_hook_owners_are_not_wiped(tmp_path):
    first_source, first = install_owner(tmp_path, "arbitrary/aurora")
    survivor_source, survivor = install_owner(tmp_path, "different/nebula")
    config = tmp_path / ".omp/hooks.json"
    payload = json.loads(config.read_text())
    payload["localSetting"] = 7
    payload["hooks"]["ForeignEvent"] = [{"unrelated": True}]
    config.write_text(json.dumps(payload))
    lock = LockFile(
        dependencies={first.get_unique_key(): first, survivor.get_unique_key(): survivor}
    )
    shutil.rmtree(first_source)
    result = reconcile_removed_native_hook_owners(lock, {first.get_unique_key()}, tmp_path)
    assert result["errors"] == 0
    payload = json.loads(config.read_text())
    assert payload["localSetting"] == 7
    assert payload["hooks"]["ForeignEvent"] == [{"unrelated": True}]
    owned = payload["hooks"]["PreToolUse"]
    assert len(owned) == 1
    assert owned[0]["hooks"][0]["apm"]["root"] == str(survivor_source.resolve())
    assert (tmp_path / ".omp/extensions/apm-hooks-project/index.ts").exists()


def test_removed_owner_cleanup_never_resolves_preserved_escaping_sources(tmp_path):
    source, dependency = install_owner(tmp_path, "arbitrary/aurora")
    outside = tmp_path / "outside"
    outside.mkdir()
    preserved = tmp_path / "apm_modules" / "acme" / "shared-lib"
    preserved.parent.mkdir(parents=True)
    preserved.symlink_to(outside)
    candidate = LockedDependency(
        repo_url="acme/shared-lib", depth=2, resolved_by="arbitrary/aurora"
    )
    lock = LockFile(
        dependencies={
            dependency.get_unique_key(): dependency,
            candidate.get_unique_key(): candidate,
        }
    )
    shutil.rmtree(source)

    result = reconcile_removed_native_hook_owners(lock, {dependency.get_unique_key()}, tmp_path)

    assert result["errors"] == 0
    assert not (tmp_path / ".omp/hooks.json").exists()
    assert preserved.is_symlink()
    assert outside.is_dir()


def test_edited_runtime_retains_retryable_ownership(tmp_path):
    _, dependency = install_owner(tmp_path, "arbitrary/aurora")
    lock = LockFile(dependencies={dependency.get_unique_key(): dependency})
    bridge = tmp_path / ".omp/extensions/apm-hooks-project/index.ts"
    bridge.write_text("// user edit\n")
    result = reconcile_removed_native_hook_owners(lock, {dependency.get_unique_key()}, tmp_path)
    assert result["errors"] > 0
    cleanup = remove_stale_deployed_files(
        set(dependency.deployed_files),
        tmp_path,
        recorded_hashes=dependency.deployed_file_hashes,
        dep_key=dependency.get_unique_key(),
        targets=[KNOWN_TARGETS["omp"]],
        diagnostics=DiagnosticCollector(),
        prior_lockfile=lock,
    )
    assert set(dependency.deployed_files).issubset(cleanup.retained)
    assert bridge.read_text() == "// user edit\n"


def test_missing_shared_runtime_claims_can_retire_after_native_cleanup(tmp_path):
    _, dependency = install_owner(tmp_path, "arbitrary/aurora")
    lock = LockFile(dependencies={dependency.get_unique_key(): dependency})
    assert (
        reconcile_removed_native_hook_owners(lock, {dependency.get_unique_key()}, tmp_path)[
            "errors"
        ]
        == 0
    )
    cleanup = remove_stale_deployed_files(
        set(dependency.deployed_files),
        tmp_path,
        recorded_hashes=dependency.deployed_file_hashes,
        dep_key=dependency.get_unique_key(),
        targets=[KNOWN_TARGETS["omp"]],
        diagnostics=DiagnosticCollector(),
        prior_lockfile=lock,
    )
    assert cleanup.retained == []


def test_target_contraction_preserves_edited_runtime_and_lock_claims(tmp_path):
    from apm_cli.install.manifest_reconcile import reconcile_deployed_state

    _, dependency = install_owner(tmp_path, "arbitrary/aurora")
    lock = LockFile(dependencies={dependency.get_unique_key(): dependency})
    bridge = tmp_path / ".omp/extensions/apm-hooks-project/index.ts"
    bridge.write_text("// user edit\n")
    before = list(dependency.deployed_files)
    with pytest.raises(RuntimeError, match="cleanup is incomplete"):
        reconcile_deployed_state(
            project_root=tmp_path,
            lockfile=lock,
            active_targets=[KNOWN_TARGETS["claude"]],
            declared_targets=[KNOWN_TARGETS["claude"]],
            diagnostics=DiagnosticCollector(),
        )
    assert dependency.deployed_files == before
    assert bridge.read_text() == "// user edit\n"


@pytest.mark.parametrize("edited", [False, True])
def test_prune_cleans_dropped_omp_before_releasing_dependency_lock(tmp_path, monkeypatch, edited):
    from click.testing import CliRunner

    from apm_cli.commands.prune import prune
    from apm_cli.deps.lockfile import get_lockfile_path

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "isolated-home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "isolated-config"))
    _, dependency = install_owner(tmp_path, "arbitrary/aurora")
    (tmp_path / "apm.yml").write_text(
        "name: project\nversion: 1.0.0\ntargets: [claude]\ndependencies:\n  apm: []\n"
    )
    lock_path = get_lockfile_path(tmp_path)
    LockFile(dependencies={dependency.get_unique_key(): dependency}).write(lock_path)
    bridge = tmp_path / ".omp/extensions/apm-hooks-project/index.ts"
    if edited:
        bridge.write_text("// operator edit\n")
    result = CliRunner().invoke(prune, [])
    if edited:
        assert result.exit_code != 0
        assert bridge.read_text() == "// operator edit\n"
        assert LockFile.read(lock_path).get_dependency(dependency.get_unique_key()) is not None
    else:
        assert result.exit_code == 0, result.output
        assert not bridge.exists()
        remaining = LockFile.read(lock_path)
        assert remaining is None or remaining.get_dependency(dependency.get_unique_key()) is None


@pytest.mark.parametrize("edited", [False, True])
def test_uninstall_cleans_dropped_omp_before_releasing_manifest(tmp_path, monkeypatch, edited):
    from click.testing import CliRunner

    from apm_cli.commands.uninstall.cli import uninstall
    from apm_cli.deps.lockfile import get_lockfile_path
    from apm_cli.utils.yaml_io import load_yaml

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "isolated-home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "isolated-config"))
    _, dependency = install_owner(tmp_path, "arbitrary/aurora")
    manifest = tmp_path / "apm.yml"
    manifest.write_text(
        "name: project\nversion: 1.0.0\ntargets: [claude]\ndependencies:\n  apm: [arbitrary/aurora]\n"
    )
    lock_path = get_lockfile_path(tmp_path)
    LockFile(dependencies={dependency.get_unique_key(): dependency}).write(lock_path)
    bridge = tmp_path / ".omp/extensions/apm-hooks-project/index.ts"
    if edited:
        bridge.write_text("// operator edit\n")
    result = CliRunner().invoke(uninstall, ["arbitrary/aurora"])
    if edited:
        assert result.exit_code != 0
        assert bridge.read_text() == "// operator edit\n"
        assert "arbitrary/aurora" in load_yaml(manifest)["dependencies"]["apm"]
        assert LockFile.read(lock_path).get_dependency(dependency.get_unique_key()) is not None
    else:
        assert result.exit_code == 0, result.output
        assert not bridge.exists()
        assert "arbitrary/aurora" not in load_yaml(manifest).get("dependencies", {}).get("apm", [])


def test_dependency_uninstall_preserves_first_party_omp_handlers(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from apm_cli.commands.uninstall.cli import uninstall
    from apm_cli.deps.lockfile import get_lockfile_path
    from apm_cli.install.project_package import build_project_local_package_info

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "isolated-home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "isolated-config"))
    (tmp_path / "apm.yml").write_text(
        "name: project\nversion: 1.0.0\ntargets: [omp]\ndependencies:\n  apm: [arbitrary/aurora]\n"
    )
    (tmp_path / ".env").write_text("PRIVATE_PROJECT_SECRET=untouched\n")
    authored = tmp_path / ".apm/hooks/hooks.json"
    authored.parent.mkdir(parents=True)
    authored.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [{"hooks": [{"type": "command", "command": "printf firstparty"}]}]
                }
            }
        )
    )
    local_result = HookIntegrator().integrate_hooks_for_target(
        KNOWN_TARGETS["omp"], build_project_local_package_info(tmp_path), tmp_path
    )
    _, dependency = install_owner(tmp_path, "arbitrary/aurora")
    local_paths = [path.relative_to(tmp_path).as_posix() for path in local_result.target_paths]
    local_hashes = {path: compute_file_hash(tmp_path / path) for path in local_paths}
    lock_path = get_lockfile_path(tmp_path)
    LockFile(
        dependencies={dependency.get_unique_key(): dependency},
        local_deployed_files=local_paths,
        local_deployed_file_hashes=local_hashes,
    ).write(lock_path)
    result = CliRunner().invoke(uninstall, ["arbitrary/aurora"])
    assert result.exit_code == 0, result.output
    handlers = json.loads((tmp_path / ".omp/hooks.json").read_text())["hooks"]["PreToolUse"]
    assert [entry["hooks"][0]["command"] for entry in handlers] == ["printf firstparty"]
    assert (tmp_path / ".omp/extensions/apm-hooks-project/index.ts").exists()
    assert (tmp_path / ".env").read_text() == "PRIVATE_PROJECT_SECRET=untouched\n"
    remaining = LockFile.read(lock_path)
    assert set(local_paths).issubset(remaining.local_deployed_files)
    assert all(
        remaining.local_deployed_file_hashes[path] == digest
        for path, digest in local_hashes.items()
    )
