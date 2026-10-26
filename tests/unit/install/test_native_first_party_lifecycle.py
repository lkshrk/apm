"""Native lifecycle regressions for project-local authority and user bundle ownership."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from apm_cli.cli import cli
from apm_cli.core.scope import InstallScope
from apm_cli.install.services import integrate_local_bundle
from apm_cli.integration.extension_integrator import ExtensionIntegrator
from apm_cli.integration.targets import KNOWN_TARGETS
from tests.utils.isolated_apm_environment import IsolatedApmEnvironment


@pytest.fixture(autouse=True)
def _reset_console_state():
    """Root CLI JSON output changes the process-wide Rich stderr routing."""
    from apm_cli.utils.console import _reset_console

    yield
    _reset_console()


def _project(tmp_path, monkeypatch):
    isolated = IsolatedApmEnvironment.create(tmp_path / "isolated", base_env=os.environ)
    for name, value in isolated.subprocess_env().items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("PI_CODING_AGENT_DIR", raising=False)
    monkeypatch.chdir(isolated.work_root)
    (isolated.work_root / "apm.yml").write_text("name: local-project\nversion: 1.0.0\n")
    (isolated.work_root / ".env").write_text("SECRET=project-only\n")
    ambient = isolated.work_root / ".omp" / "extensions" / "user.ts"
    ambient.parent.mkdir(parents=True)
    ambient.write_text("export default api => {};\n")
    return isolated.work_root, ambient


def _install(target):
    result = CliRunner().invoke(
        cli,
        [
            "install",
            "--target",
            target,
            "--no-policy",
            "--parallel-downloads",
            "0",
        ],
    )
    assert result.exit_code == 0, result.output


def _declare_targets(project, *targets):
    import yaml

    manifest = project / "apm.yml"
    data = yaml.safe_load(manifest.read_text())
    data["targets"] = list(targets)
    manifest.write_text(yaml.safe_dump(data))


def _assert_clean_replay(project):
    from apm_cli.deps.lockfile import LockFile
    from apm_cli.policy.ci_checks import _check_drift

    lock = LockFile.read(project / "apm.lock.yaml")
    assert lock is not None
    result, findings = _check_drift(project, lock, cache_only=True)
    assert result.passed, result.message
    assert "skip" not in result.message.lower(), result.message
    assert findings == []


def test_first_party_hooks_second_install_and_retarget_preserve_ambient_code(tmp_path, monkeypatch):
    project, ambient = _project(tmp_path, monkeypatch)
    _declare_targets(project, "omp")
    descriptor = project / ".apm" / "hooks" / "start.json"
    descriptor.parent.mkdir(parents=True)
    descriptor.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [{"type": "command", "command": "printf local-hook"}],
                        }
                    ]
                }
            }
        )
    )
    ambient_bytes = ambient.read_bytes()
    _install("omp")
    bridge = project / ".omp" / "extensions" / "apm-hooks-project" / "index.ts"
    assert bridge.is_file()
    _install("omp")
    assert bridge.is_file()
    assert ambient.read_bytes() == ambient_bytes
    assert not list((project / ".omp" / "extensions").rglob(".env"))
    assert not (project / ".omp" / "extensions" / "_local").exists()
    _assert_clean_replay(project)
    _declare_targets(project, "claude")
    _install("claude")
    assert not bridge.exists()
    assert ambient.read_bytes() == ambient_bytes
    assert (project / ".env").read_text() == "SECRET=project-only\n"
    assert (project / ".claude" / "settings.json").is_file()


def test_first_party_native_second_install_and_retarget_use_only_bounded_source(
    tmp_path, monkeypatch
):
    project, ambient = _project(tmp_path, monkeypatch)
    _declare_targets(project, "omp")
    source = project / ".apm" / "extensions"
    module = source / "widget" / "index.ts"
    module.parent.mkdir(parents=True)
    module.write_text("export default api => {};\n")
    (source / "resource.json").write_text('{"value": 1}\n')
    _install("omp")
    deployed = project / ".omp" / "extensions" / "_local"
    assert (deployed / "widget" / "index.ts").read_bytes() == module.read_bytes()
    assert (deployed / "resource.json").is_file()
    assert not (deployed / ".env").exists()
    assert not (deployed / ".omp").exists()
    _install("omp")
    assert (deployed / "widget" / "index.ts").is_file()
    assert ambient.is_file()
    _assert_clean_replay(project)
    _declare_targets(project, "claude")
    _install("claude")
    assert not deployed.exists()
    assert ambient.is_file()
    assert (project / ".env").read_text() == "SECRET=project-only\n"


@pytest.mark.parametrize("custom_root", [False, True])
def test_user_native_local_bundle_reinstall_and_removal_share_record_identity(
    tmp_path, monkeypatch, custom_root
):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    if custom_root:
        monkeypatch.setenv("PI_CODING_AGENT_DIR", str(tmp_path / "custom-agent"))
    else:
        monkeypatch.delenv("PI_CODING_AGENT_DIR", raising=False)
    target = KNOWN_TARGETS["omp"].for_scope(user_scope=True)
    bundle = tmp_path / "bundle"
    source = bundle / ".omp" / "extensions" / "native"
    source.mkdir(parents=True)
    (source / "package.json").write_text(json.dumps({"omp": {"extensions": ["index.ts"]}}))
    (source / "index.ts").write_text("export default api => {};\n")
    (source / "resource.json").write_text('{"value": 1}\r\n')
    pack_files = {
        path.relative_to(bundle).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in source.iterdir()
    }
    info = SimpleNamespace(
        source_dir=bundle,
        package_id="native-bundle",
        lockfile={"pack": {"bundle_files": pack_files}},
    )
    approval = "native-bundle-content"
    options = {
        "targets": [target],
        "scope": InstallScope.USER,
        "allow_executables": {approval: {"extensions": True}},
        "approval_key": approval,
        "create_config": False,
    }
    first = integrate_local_bundle(info, home, **options)
    paths = set(first["deployed_files"])
    assert paths
    if not custom_root:
        assert all(not Path(path).is_absolute() for path in paths)
    second = integrate_local_bundle(
        info,
        home,
        **options,
        managed_files=paths,
        managed_file_hashes=first["deployed_file_hashes"],
    )
    assert set(second["deployed_files"]) == paths
    deployed = target.deploy_path(home) / "extensions" / "native"
    assert (deployed / "resource.json").read_bytes() == (source / "resource.json").read_bytes()
    stats = ExtensionIntegrator().sync_for_target(
        target,
        None,
        home,
        managed_files=paths,
        managed_file_hashes=second["deployed_file_hashes"],
    )
    assert stats["errors"] == 0
    assert not deployed.exists()


def test_uninstall_dependency_preserves_first_party_native_and_ambient_files(tmp_path, monkeypatch):
    import yaml

    from apm_cli.deps.lockfile import _SELF_KEY, LockFile
    from apm_cli.integration.extension_integrator import RECEIPT_FILENAME
    from apm_cli.models.dependency import DependencyReference

    project, ambient = _project(tmp_path, monkeypatch)
    own_source = project / ".apm" / "extensions" / "own" / "index.ts"
    own_source.parent.mkdir(parents=True)
    own_source.write_text("export default api => {};\n")
    dependency_source = tmp_path / "dependency-native"
    dependency_source.mkdir()
    (dependency_source / "apm.yml").write_text(
        "name: dependency-native\nversion: 1.0.0\ntargets: [omp]\n"
    )
    (dependency_source / "package.json").write_text(
        json.dumps({"omp": {"extensions": ["dependency.ts"]}})
    )
    (dependency_source / "dependency.ts").write_text("export default api => {};\n")
    reference = DependencyReference.parse(str(dependency_source))
    (project / "apm.yml").write_text(
        yaml.safe_dump(
            {
                "name": "local-project",
                "version": "1.0.0",
                "dependencies": {"apm": [str(dependency_source)]},
                "executables": {"allow": {reference.to_canonical(): {"extensions": True}}},
            }
        )
    )
    _install("omp")
    _install("omp")
    own_bundle = project / ".omp" / "extensions" / "_local"
    assert (own_bundle / "own" / "index.ts").is_file()
    own_before = {
        path.relative_to(own_bundle): path.read_bytes()
        for path in own_bundle.rglob("*")
        if path.is_file()
    }
    ambient_before = ambient.read_bytes()
    lock = LockFile.read(project / "apm.lock.yaml")
    assert lock is not None
    dependency = next(dep for dep in lock.dependencies.values() if dep.local_path != _SELF_KEY)
    dependency_roots = {
        (project / relative).parent
        for relative in dependency.deployed_files
        if Path(relative).name == RECEIPT_FILENAME
    }
    assert len(dependency_roots) == 1
    assert own_bundle not in dependency_roots
    result = CliRunner().invoke(cli, ["uninstall", dependency.get_unique_key()])
    assert result.exit_code == 0, result.output
    assert all(not root.exists() for root in dependency_roots)
    assert {
        path.relative_to(own_bundle): path.read_bytes()
        for path in own_bundle.rglob("*")
        if path.is_file()
    } == own_before
    assert ambient.read_bytes() == ambient_before
    assert (project / ".env").read_text() == "SECRET=project-only\n"
    remaining = LockFile.read(project / "apm.lock.yaml")
    assert remaining is not None
    assert (own_bundle / RECEIPT_FILENAME).relative_to(
        project
    ).as_posix() in remaining.local_deployed_files


def test_user_imperative_native_bundle_survives_unrelated_dependency_uninstall(
    tmp_path, monkeypatch
):
    import yaml

    from apm_cli.bundle.local_bundle import detect_local_bundle
    from apm_cli.core.deployment_ledger import DeploymentLedgerCodec
    from apm_cli.deps.lockfile import LockFile
    from apm_cli.security.executables import local_bundle_approval_key

    _project(tmp_path, monkeypatch)
    home = Path.home()
    metadata = home / ".apm"
    metadata.mkdir(parents=True, exist_ok=True)
    dependency_source = tmp_path / "unrelated-skill"
    skill = dependency_source / ".apm" / "skills" / "unrelated" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: unrelated\ndescription: Unrelated skill\n---\nInstructions.\n")
    (dependency_source / "apm.yml").write_text(
        "name: unrelated-skill\nversion: 1.0.0\ntargets: [omp]\n"
    )
    bundle = tmp_path / "offline-native"
    source = bundle / ".omp" / "extensions" / "offline-native"
    source.mkdir(parents=True)
    (source / "package.json").write_text(json.dumps({"omp": {"extensions": ["index.ts"]}}))
    (source / "index.ts").write_text("export default api => {};\n")
    (bundle / "plugin.json").write_text(
        json.dumps({"id": "offline-native", "name": "Offline native", "version": "1.0.0"})
    )
    pack_files = {
        path.relative_to(bundle).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in source.iterdir()
    }
    (bundle / "apm.lock.yaml").write_text(
        yaml.safe_dump(
            {
                "pack": {"format": "plugin", "target": "omp", "bundle_files": pack_files},
                "dependencies": [
                    {"repo_url": "owner/offline-native", "deployed_files": list(pack_files)}
                ],
            }
        )
    )
    info = detect_local_bundle(bundle)
    assert info is not None
    approval = local_bundle_approval_key(
        info.package_id,
        str(info.plugin_json.get("version") or ""),
        info.source_dir,
        info.lockfile,
    )
    (metadata / "apm.yml").write_text(
        yaml.safe_dump(
            {
                "name": "user-native",
                "version": "1.0.0",
                "dependencies": {"apm": [str(dependency_source)]},
                "executables": {"allow": {approval: {"extensions": True}}},
            }
        )
    )
    result = CliRunner().invoke(
        cli, ["install", "--global", "--target", "omp", "--no-policy", "--parallel-downloads", "0"]
    )
    assert result.exit_code == 0, result.output
    deployed = home / ".omp" / "agent" / "extensions" / "offline-native"
    for _ in range(2):
        result = CliRunner().invoke(
            cli, ["install", str(bundle), "--global", "--target", "omp", "--no-policy"]
        )
        assert result.exit_code == 0, result.output
        assert (deployed / "index.ts").read_bytes() == (source / "index.ts").read_bytes(), (
            result.output
        )
        installed = LockFile.read(metadata / "apm.lock.yaml")
        assert installed is not None
        bundle_paths = DeploymentLedgerCodec.local_bundle_paths(installed)
        assert (deployed / "index.ts").relative_to(home).as_posix() in bundle_paths
        assert all(not Path(path).is_absolute() for path in bundle_paths)
        assert not (home / "apm.lock.yaml").exists()
    before = {
        path.relative_to(deployed): path.read_bytes()
        for path in deployed.rglob("*")
        if path.is_file()
    }
    lock = LockFile.read(metadata / "apm.lock.yaml")
    assert lock is not None
    dependency = next(
        dep for dep in lock.dependencies.values() if dep.local_path == str(dependency_source)
    )
    result = CliRunner().invoke(cli, ["uninstall", dependency.get_unique_key(), "--global"])
    assert result.exit_code == 0, result.output
    assert {
        path.relative_to(deployed): path.read_bytes()
        for path in deployed.rglob("*")
        if path.is_file()
    } == before
    remaining = LockFile.read(metadata / "apm.lock.yaml")
    assert remaining is not None
    assert set(lock.local_deployed_files) <= set(remaining.local_deployed_files)
    assert DeploymentLedgerCodec.local_bundle_paths(
        remaining
    ) == DeploymentLedgerCodec.local_bundle_paths(lock)


def test_global_native_bundle_does_not_use_project_executable_approval(tmp_path, monkeypatch):
    import yaml

    from apm_cli.bundle.local_bundle import detect_local_bundle
    from apm_cli.security.executables import local_bundle_approval_key

    project, _ambient = _project(tmp_path, monkeypatch)
    home = Path.home()
    metadata = home / ".apm"
    metadata.mkdir(parents=True, exist_ok=True)
    (metadata / "apm.yml").write_text(
        yaml.safe_dump(
            {
                "name": "user-native",
                "version": "1.0.0",
                "executables": {"allow": {}},
            }
        )
    )
    bundle = tmp_path / "offline-native"
    source = bundle / ".omp" / "extensions" / "offline-native"
    source.mkdir(parents=True)
    (source / "package.json").write_text(json.dumps({"omp": {"extensions": ["index.ts"]}}))
    (source / "index.ts").write_text("export default api => {};\n")
    (bundle / "plugin.json").write_text(json.dumps({"id": "offline-native", "version": "1.0.0"}))
    pack_files = {
        path.relative_to(bundle).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in source.iterdir()
    }
    (bundle / "apm.lock.yaml").write_text(
        yaml.safe_dump(
            {
                "pack": {"format": "plugin", "target": "omp", "bundle_files": pack_files},
                "dependencies": [
                    {"repo_url": "owner/offline-native", "deployed_files": list(pack_files)}
                ],
            }
        )
    )
    info = detect_local_bundle(bundle)
    assert info is not None
    approval = local_bundle_approval_key(
        info.package_id,
        str(info.plugin_json.get("version") or ""),
        info.source_dir,
        info.lockfile,
    )
    (project / "apm.yml").write_text(
        yaml.safe_dump(
            {
                "name": "local-project",
                "version": "1.0.0",
                "executables": {"allow": {approval: {"extensions": True}}},
            }
        )
    )

    result = CliRunner().invoke(
        cli, ["install", str(bundle), "--global", "--target", "omp", "--no-policy"]
    )

    assert result.exit_code == 0, result.output
    assert "Blocked native extensions" in result.output
    assert not (home / ".omp" / "agent" / "extensions" / "offline-native").exists()
    assert not (metadata / "apm.lock.yaml").exists()
    assert not (home / "apm.lock.yaml").exists()


def test_first_party_native_frozen_install_survives_checkout_relocation(tmp_path, monkeypatch):
    import shutil

    from apm_cli.deps.lockfile import LockFile

    project, _ambient = _project(tmp_path, monkeypatch)
    source = project / ".apm" / "extensions" / "widget" / "index.ts"
    source.parent.mkdir(parents=True)
    source.write_text("export default api => {};\n")
    _install("omp")
    before = LockFile.read(project / "apm.lock.yaml")
    assert before is not None
    relocated = tmp_path / "different checkout name"
    shutil.copytree(
        project, relocated, ignore=shutil.ignore_patterns(".omp", "apm_modules", ".git")
    )
    monkeypatch.chdir(relocated)
    result = CliRunner().invoke(
        cli,
        [
            "install",
            "--frozen",
            "--target",
            "omp",
            "--no-policy",
            "--parallel-downloads",
            "0",
        ],
    )
    assert result.exit_code == 0, result.output
    deployed = relocated / ".omp" / "extensions" / "_local" / "widget" / "index.ts"
    assert deployed.read_bytes() == source.read_bytes()
    after = LockFile.read(relocated / "apm.lock.yaml")
    assert after is not None
    assert after.local_deployed_files == before.local_deployed_files


@pytest.mark.parametrize("edited", [False, True])
def test_unrelated_uninstall_preserves_native_dependency_without_rematerializing(
    tmp_path, monkeypatch, edited
):
    import yaml

    from apm_cli.deps.lockfile import LockFile
    from apm_cli.integration.extension_integrator import RECEIPT_FILENAME
    from apm_cli.models.dependency import DependencyReference

    project, _ambient = _project(tmp_path, monkeypatch)
    native_source = tmp_path / "native-survivor"
    unrelated_source = tmp_path / "unrelated-dependency"
    for source, skill_name in (
        (native_source, "retained-skill"),
        (unrelated_source, "removed-skill"),
    ):
        skill = source / ".apm" / "skills" / skill_name / "SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_text(
            f"---\nname: {skill_name}\ndescription: Lifecycle fixture\n---\nInstructions.\n"
        )
        (source / "apm.yml").write_text(f"name: {source.name}\nversion: 1.0.0\ntargets: [omp]\n")
    original_module = "export default api => {}; // installed version\n"
    (native_source / "package.json").write_text(
        json.dumps({"omp": {"extensions": ["survivor.ts"]}})
    )
    (native_source / "survivor.ts").write_text(original_module)
    reference = DependencyReference.parse(str(native_source))
    (project / "apm.yml").write_text(
        yaml.safe_dump(
            {
                "name": "local-project",
                "version": "1.0.0",
                "dependencies": {"apm": [str(native_source), str(unrelated_source)]},
                "executables": {"allow": {reference.to_canonical(): {"extensions": True}}},
            }
        )
    )
    _install("omp")
    lock = LockFile.read(project / "apm.lock.yaml")
    assert lock is not None
    survivor = next(
        dep for dep in lock.dependencies.values() if dep.local_path == str(native_source)
    )
    removed = next(
        dep for dep in lock.dependencies.values() if dep.local_path == str(unrelated_source)
    )
    receipt = next(
        project / relative
        for relative in survivor.deployed_files
        if Path(relative).name == RECEIPT_FILENAME
    )
    entry = receipt.parent / "survivor.ts"
    receipt_before = receipt.read_bytes()
    hashes_before = dict(survivor.deployed_file_hashes)
    claims_before = set(survivor.deployed_files)
    retained_skills = {
        project / relative: (project / relative).read_bytes()
        for relative in survivor.deployed_files
        if relative.startswith(".agents/skills/") and relative.endswith("SKILL.md")
    }
    assert retained_skills
    cache_entry = (
        survivor.to_dependency_ref().get_install_path(project / "apm_modules") / "survivor.ts"
    )
    cache_before = cache_entry.read_bytes()
    if edited:
        entry.write_text("export default api => {}; // operator edit\n")
    entry_before = entry.read_bytes()
    (native_source / "survivor.ts").write_text(
        "export default api => {}; // newer source must not be installed\n"
    )

    result = CliRunner().invoke(cli, ["uninstall", removed.get_unique_key()])
    assert result.exit_code == 0, result.output
    assert entry.read_bytes() == entry_before
    assert receipt.read_bytes() == receipt_before
    assert cache_entry.read_bytes() == cache_before
    assert all(path.read_bytes() == content for path, content in retained_skills.items())
    assert all(not (project / relative).exists() for relative in removed.deployed_files)
    after = LockFile.read(project / "apm.lock.yaml")
    assert after is not None
    retained = after.dependencies[survivor.get_unique_key()]
    assert retained.deployed_file_hashes == hashes_before
    assert set(retained.deployed_files) == claims_before


@pytest.mark.parametrize("kind", ["hooks", "extensions"])
def test_cli_target_narrowing_preserves_other_first_party_targets(tmp_path, monkeypatch, kind):
    project, ambient = _project(tmp_path, monkeypatch)
    if kind == "hooks":
        source = project / ".apm/hooks/hooks.json"
        source.parent.mkdir(parents=True)
        source.write_text(
            json.dumps(
                {
                    "hooks": {
                        "PreToolUse": [
                            {
                                "hooks": [{"type": "command", "command": "printf authored"}],
                            }
                        ]
                    }
                }
            )
        )
        deployed = project / ".omp/hooks.json"
    else:
        source = project / ".apm/extensions/widget/index.ts"
        source.parent.mkdir(parents=True)
        source.write_text("export default api => {};\n")
        deployed = project / ".omp/extensions/_local/widget/index.ts"
    _install("omp")
    before = deployed.read_bytes()
    _install("claude")
    assert deployed.read_bytes() == before
    assert ambient.is_file()


def test_cli_audit_matches_dependency_then_first_party_hook_install_order(tmp_path, monkeypatch):
    import yaml

    from apm_cli.models.dependency import DependencyReference

    project, ambient = _project(tmp_path, monkeypatch)
    personal = project / ".omp/extensions/personal/index.ts"
    personal.parent.mkdir()
    personal.write_text("export default api => {};\n")
    dependency = tmp_path / "bridge-dependency"
    dep_hook = dependency / "hooks/hooks.json"
    dep_hook.parent.mkdir(parents=True)
    dep_command = 'node "${CLAUDE_PLUGIN_ROOT}/scripts/dependency.cjs"'
    local_command = 'node "${CLAUDE_PLUGIN_ROOT}/scripts/local.cjs"'
    dep_hook.write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "hooks": [{"type": "command", "command": dep_command, "timeout": 5}],
                        }
                    ]
                }
            }
        )
    )
    for root, script_name, text in (
        (dependency, "dependency.cjs", "dependency context"),
        (project, "local.cjs", "authored context"),
    ):
        script = root / "scripts" / script_name
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(
            "process.stdout.write(require('node:fs').readFileSync(require('node:path').join(__dirname, '../assets/message.txt'), 'utf8'));\n"
        )
        asset = root / "assets/message.txt"
        asset.parent.mkdir(parents=True, exist_ok=True)
        asset.write_text(text)
    local_hook = project / ".apm/hooks/local.json"
    local_hook.parent.mkdir(parents=True)
    local_hook.write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "hooks": [{"type": "command", "command": local_command, "timeout": 5}],
                        }
                    ]
                }
            }
        )
    )
    reference = DependencyReference.parse(str(dependency))
    (project / "apm.yml").write_text(
        yaml.safe_dump(
            {
                "name": "mixed-hook-project",
                "version": "1.0.0",
                "targets": ["omp"],
                "dependencies": {"apm": [str(dependency)]},
                "executables": {"allow": {reference.to_canonical(): {"hooks": True}}},
            }
        )
    )
    _install("omp")
    config = project / ".omp/hooks.json"
    sidecar = project / ".omp/apm-hooks.json"
    installed = {path: path.read_bytes() for path in (config, sidecar, ambient, personal)}
    handlers = json.loads(installed[config])["hooks"]["SessionStart"]
    assert [entry["hooks"][0]["command"] for entry in handlers] == [dep_command, local_command]
    assert [entry["hooks"][0]["apm"]["root"] for entry in handlers] == [
        str(reference.get_install_path(project / "apm_modules").resolve()),
        str(project.resolve()),
    ]
    assert len({entry["hooks"][0]["apm"]["dataDir"] for entry in handlers}) == 2
    _install("omp")
    assert {path: path.read_bytes() for path in installed} == installed
    audited = CliRunner().invoke(cli, ["audit", "--ci", "--no-policy", "--format", "json"])
    assert audited.stdout, f"output={audited.output!r}; exception={audited.exception!r}"
    document = json.loads(audited.stdout)
    assert audited.exit_code == 0, audited.output
    assert document["passed"] is True
    drift = next(check for check in document["checks"] if check["name"] == "drift")
    assert drift["passed"] is True
    assert "skip" not in drift["message"].lower()
    assert {path: path.read_bytes() for path in installed} == installed
