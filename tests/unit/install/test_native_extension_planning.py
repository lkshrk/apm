"""Native executable planning keeps resources, approval, and runtimes separate."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from apm_cli.bundle.lockfile_enrichment import _filter_files_by_target
from apm_cli.bundle.plugin_exporter import (
    _collect_apm_components,
    _plugin_rel_for_deployed_path,
    _require_attested_native_sources,
)
from apm_cli.install.audit_target_roots import canvas_deploy_prefixes, extension_deploy_prefixes
from apm_cli.install.deployable_source_plan import DeployableSourcePlan
from apm_cli.install.exec_gate import check_executable_approval
from apm_cli.install.local_bundle_paths import (
    bundle_deploy_relative_path,
    known_bundle_deploy_prefixes,
    target_bundle_deploy_prefixes,
)
from apm_cli.integration.extension_bundle_install import (
    integrate_native_bundle_plans,
    plan_native_bundle_files,
)
from apm_cli.integration.targets import KNOWN_TARGETS


def _native(root: Path, entry: str = "index.ts") -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({"omp": {"extensions": [entry]}}))
    (root / entry).parent.mkdir(parents=True, exist_ok=True)
    (root / entry).write_text("export default api => {};\n")
    (root / "assets").mkdir()
    (root / "assets" / "config.json").write_text('{"resource": true}\r\n')


def _plan(root: Path, target: str = "omp", *, approved: bool = True):
    return DeployableSourcePlan.create(
        SimpleNamespace(install_path=root),
        [KNOWN_TARGETS[target]],
        skill_subset=None,
        hooks_approved=False,
        canvas_approved=True,
        extensions_approved=approved,
        skip_bin=True,
    )


def test_native_source_plan_keeps_full_resources_and_vendored_modules(tmp_path):
    _native(tmp_path)
    dependency = tmp_path / "node_modules" / "vendored" / "index.js"
    dependency.parent.mkdir(parents=True)
    dependency.write_text("export const resource = 1;")
    (tmp_path / ".runtime-data").write_text("private asset")
    assert _plan(tmp_path).paths == frozenset(
        {
            "index.ts",
            "package.json",
            "assets/config.json",
            "node_modules/vendored/index.js",
            ".runtime-data",
        }
    )
    assert not _plan(tmp_path, approved=False).paths


@pytest.mark.parametrize("target", ["claude", "codex", "copilot"])
def test_missing_native_artifact_does_not_block_excluded_targets(tmp_path, target):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "omp": {"extensions": ["build/adapters/omp/plugin.js"]},
            }
        )
    )
    assert not _plan(tmp_path, target).paths


@pytest.mark.parametrize("approved", [True, False])
def test_missing_native_artifact_fails_selected_target_before_writes(tmp_path, approved):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "omp": {"extensions": ["build/adapters/omp/plugin.js"]},
            }
        )
    )
    with pytest.raises(ValueError, match="Missing or unsupported"):
        _plan(tmp_path, approved=approved)
    assert not (tmp_path / ".omp").exists()


def test_native_source_plan_rejects_symlink_resources(tmp_path):
    _native(tmp_path)
    (tmp_path / "linked.json").symlink_to(tmp_path / "assets" / "config.json")
    with pytest.raises(ValueError, match="unsafe path or symlink"):
        _plan(tmp_path)


def test_native_approval_is_not_canvas_or_spoofed_local_trust(tmp_path):
    package = SimpleNamespace(package=SimpleNamespace(name="native", version="1"))
    assert check_executable_approval("native", package, {"native#1": {"canvas": True}})[-1] is False
    assert (
        check_executable_approval("native", package, {"native#1": {"extensions": True}})[-1] is True
    )
    assert check_executable_approval("native", package, None) == (
        True,
        True,
        True,
        True,
        True,
        False,
    )
    assert check_executable_approval("_local", package, {})[-1] is False
    assert check_executable_approval("_local", package, {}, is_first_party=True)[-1] is True


class _GitRef:
    """A git dependency: the gate sees the host-qualified string, the lockfile the lowercase identity."""

    def __str__(self):
        return "github.com/Owner/Repo"

    def get_unique_key(self):
        return "owner/repo"


def test_grant_recorded_by_apm_approve_reaches_the_install_gate(tmp_path):
    package = SimpleNamespace(dependency_ref=_GitRef(), install_path=tmp_path)
    recorded = {"owner/repo#abc1234": {"extensions": True}, "owner/repo": {"extensions": True}}
    assert check_executable_approval("owner/repo", package, recorded)[-1] is True
    assert (
        check_executable_approval("owner/repo", package, {"other/repo": {"extensions": True}})[-1]
        is False
    )


def test_user_grant_approves_native_extensions_while_the_gate_is_disabled(tmp_path, monkeypatch):
    from dataclasses import replace

    from apm_cli.security import executables

    monkeypatch.setattr(executables, "load_user_executables", lambda **_: ({}, {}))
    trust = executables.build_exec_trust_context(
        policy=None, project_data={}, migrate_user_legacy=False
    )
    assert not trust.gate_enabled
    package = SimpleNamespace(dependency_ref=_GitRef(), install_path=tmp_path)

    def approved(context):
        install = SimpleNamespace(
            blocked_executables=[], exec_trust_ctx=context, package_exec_status={}
        )
        return check_executable_approval("owner/repo", package, None, ctx=install)[-1]

    assert approved(trust) is False
    granted = replace(trust, user_allow={"owner/repo#abc1234": {"extensions": True}})
    assert approved(granted) is True
    denied = replace(granted, user_deny={"owner/repo": {"extensions": True}})
    assert approved(denied) is False


@pytest.mark.parametrize("prefix", [".omp/extensions", ".omp/agent/extensions"])
def test_native_plugin_paths_preserve_identity_and_resource_names(prefix):
    relative = f"{prefix}/native/assets/config.json"
    assert _plugin_rel_for_deployed_path(relative, None) == relative
    omp = KNOWN_TARGETS["omp"]
    assert (
        bundle_deploy_relative_path(
            relative,
            target_bundle_deploy_prefixes(omp),
            known_bundle_deploy_prefixes(),
            target=omp,
        )
        == "extensions/native/assets/config.json"
    )
    copilot = KNOWN_TARGETS["copilot"]
    assert (
        bundle_deploy_relative_path(
            relative,
            target_bundle_deploy_prefixes(copilot),
            known_bundle_deploy_prefixes(),
            target=copilot,
        )
        is None
    )
    assert _filter_files_by_target([relative], "copilot") == ([], {})
    assert _filter_files_by_target([relative], "omp") == ([relative], {})


def test_flat_canvas_does_not_become_native_extension():
    omp = KNOWN_TARGETS["omp"]
    assert (
        bundle_deploy_relative_path(
            "extensions/canvas/extension.mjs",
            target_bundle_deploy_prefixes(omp),
            known_bundle_deploy_prefixes(),
            target=omp,
        )
        is None
    )
    assert extension_deploy_prefixes([omp]) == {".omp/extensions/"}
    assert canvas_deploy_prefixes([omp]) == set()


def _packed(tmp_path):
    bundle = tmp_path / "bundle"
    source = bundle / ".omp" / "extensions" / "native"
    _native(source)
    files = {
        path.relative_to(bundle).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in source.rglob("*")
        if path.is_file()
    }
    return bundle, source, files, tmp_path / "project"


def test_offline_native_bundle_plans_without_writes_and_installs_atomically(tmp_path):
    bundle, source, files, project = _packed(tmp_path)
    asset = source / "assets" / "config.json"
    asset.chmod(0o750)
    plans = plan_native_bundle_files(bundle, files, [KNOWN_TARGETS["omp"]], project)
    assert not project.exists()
    paths = integrate_native_bundle_plans(plans, project)
    destination = project / ".omp" / "extensions" / "native"
    assert set(paths) == set(plans[0].target_paths)
    assert (destination / "assets" / "config.json").read_bytes() == asset.read_bytes()
    assert (destination / "assets" / "config.json").stat().st_mode & 0o777 == 0o750
    managed = {path.relative_to(project).as_posix() for path in paths}
    from apm_cli.utils.content_hash import compute_file_hash

    assert plans[0].target_hashes == {path: compute_file_hash(path) for path in paths}
    assert plan_native_bundle_files(
        bundle, files, [KNOWN_TARGETS["omp"]], project, managed_files=managed
    )
    (destination / "index.ts").write_text("edited by user")
    with pytest.raises(ValueError, match="foreign or modified"):
        plan_native_bundle_files(
            bundle, files, [KNOWN_TARGETS["omp"]], project, managed_files=managed
        )
    assert (destination / "index.ts").read_text() == "edited by user"


@pytest.mark.parametrize("fault", ["missing", "unattested", "hash", "symlink"])
def test_offline_native_bundle_rejects_partial_or_tampered_tree_before_writes(tmp_path, fault):
    bundle, source, files, project = _packed(tmp_path)
    asset = source / "assets" / "config.json"
    if fault == "missing":
        asset.unlink()
    elif fault == "unattested":
        (source / "extra.json").write_text("{}")
    elif fault == "hash":
        asset.write_text("changed")
    else:
        (source / "linked.json").symlink_to(asset)
    with pytest.raises(ValueError):
        plan_native_bundle_files(bundle, files, [KNOWN_TARGETS["omp"]], project)
    assert not project.exists()


def test_offline_native_bundle_excluded_target_never_activates(tmp_path):
    bundle, source, files, project = _packed(tmp_path)
    (source / "index.ts").unlink()
    assert plan_native_bundle_files(bundle, files, [KNOWN_TARGETS["claude"]], project) == []
    assert not project.exists()


def test_missing_native_approval_does_not_block_legacy_hook_only_package(tmp_path):
    hooks = tmp_path / ".apm" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "start.json").write_text("{}")
    context = SimpleNamespace(blocked_executables=[])
    approvals = check_executable_approval(
        "hooks-only",
        SimpleNamespace(install_path=tmp_path),
        None,
        ctx=context,
    )
    assert approvals == (True, True, True, True, True, False)
    assert context.blocked_executables == []


def test_raw_native_source_pack_requires_matching_attested_payload(tmp_path):
    source = tmp_path / ".apm" / "extensions"
    _native(source)
    with pytest.raises(ValueError, match="attested installed payload"):
        _require_attested_native_sources(tmp_path, {}, "omp")
    unrelated = {".omp/extensions/other/package.json": (source / "package.json", "other")}
    with pytest.raises(ValueError, match="attested installed payload"):
        _require_attested_native_sources(tmp_path, unrelated, "omp")
    attested = {
        ".omp/extensions/_local/package.json": (source / "package.json", "_local"),
    }
    _require_attested_native_sources(tmp_path, attested, "omp")
    _require_attested_native_sources(tmp_path, {}, "claude")


def test_own_native_manifest_cannot_export_whole_project(tmp_path):
    _native(tmp_path)
    (tmp_path / ".env").write_text("SECRET=do-not-copy")
    with pytest.raises(ValueError, match=r"\.apm/extensions"):
        _require_attested_native_sources(tmp_path, {}, "omp")


def test_first_party_plan_ignores_ambient_extensions_and_bounds_resources(tmp_path):
    source = tmp_path / ".apm" / "extensions"
    _native(source)
    ambient = tmp_path / ".omp" / "extensions" / "user.ts"
    ambient.parent.mkdir(parents=True)
    ambient.write_text("export default api => {};")
    (tmp_path / ".env").write_text("SECRET=do-not-copy")
    plan = DeployableSourcePlan.create(
        SimpleNamespace(install_path=tmp_path),
        [KNOWN_TARGETS["omp"]],
        skill_subset=None,
        hooks_approved=False,
        canvas_approved=False,
        extensions_approved=True,
        skip_bin=True,
        is_first_party=True,
    )
    assert plan.paths == frozenset(
        {
            ".apm/extensions/index.ts",
            ".apm/extensions/package.json",
            ".apm/extensions/assets/config.json",
        }
    )


def test_native_apm_source_is_not_flattened_into_canvas(tmp_path):
    native = tmp_path / ".apm" / "extensions" / "native"
    native.mkdir(parents=True)
    (native / "index.ts").write_text("export default api => {};")
    canvas = native.parent / "canvas"
    canvas.mkdir()
    (canvas / "extension.mjs").write_text("export default {};")
    (canvas / "asset.json").write_text("{}")
    paths = {relative for _source, relative in _collect_apm_components(tmp_path / ".apm")}
    assert paths == {"extensions/canvas/extension.mjs", "extensions/canvas/asset.json"}


def test_offline_native_receipt_preserves_complex_owner_and_lock_baseline(tmp_path):
    import shutil

    from apm_cli.integration.extension_integrator import RECEIPT_FILENAME, ExtensionIntegrator
    from apm_cli.utils.content_hash import compute_file_hash

    source = tmp_path / "source"
    _native(source)
    project = tmp_path / "project"
    result = ExtensionIntegrator().integrate_extensions_for_target(
        KNOWN_TARGETS["omp"],
        SimpleNamespace(install_path=source),
        project,
        package_name="org/repo",
        trust_extensions=True,
    )
    managed = {path.relative_to(project).as_posix() for path in result.target_paths}
    baseline = {
        path.relative_to(project).as_posix(): compute_file_hash(path)
        for path in result.target_paths
    }
    bundle = tmp_path / "bundle"
    shutil.copytree(project / ".omp", bundle / ".omp")
    pack_files = {
        path.relative_to(bundle).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in bundle.rglob("*")
        if path.is_file()
    }
    plans = plan_native_bundle_files(
        bundle,
        pack_files,
        [KNOWN_TARGETS["omp"]],
        project,
        managed_files=managed,
        managed_file_hashes=baseline,
    )
    assert plans[0].package_name == "org/repo"
    assert set(plans[0].target_paths) == set(result.target_paths)
    paths = integrate_native_bundle_plans(
        plans,
        project,
        managed_files=managed,
        managed_file_hashes=baseline,
    )
    receipt = next(path for path in paths if path.name == RECEIPT_FILENAME)
    assert json.loads(receipt.read_text())["owner"] == "org/repo"
    receipt.write_text(receipt.read_text() + "\n")
    with pytest.raises(ValueError, match="foreign or modified"):
        plan_native_bundle_files(
            bundle,
            pack_files,
            [KNOWN_TARGETS["omp"]],
            project,
            managed_files=managed,
            managed_file_hashes=baseline,
        )


def test_omp_hook_replay_canonicalizes_paths_without_hiding_handler_drift(tmp_path):
    from apm_cli.deps.lockfile import LockFile
    from apm_cli.install.audit_target_roots import canonicalize_omp_hook_replay
    from apm_cli.install.drift import diff_scratch_against_project

    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    cached_package = tmp_path / "cache" / "org" / "repo"
    live_package = project / "apm_modules" / "org" / "repo"
    target = KNOWN_TARGETS["omp"]

    def documents(root, package_root):
        target_root = target.deploy_path(root)
        target_root.mkdir(parents=True)
        entry = {
            "matcher": "Read",
            "hooks": [
                {
                    "type": "command",
                    "command": f"node '{package_root}/scripts/check.js'",
                    "apm": {
                        "owner": "org/repo",
                        "root": str(package_root),
                        "dataDir": str(target_root / "hook-data" / "stable"),
                    },
                }
            ],
        }
        config = {"hooks": {"PreToolUse": [entry]}}
        sidecar = {"PreToolUse": [{**entry, "_apm_source": "org/repo"}]}
        (target_root / "hooks.json").write_text(json.dumps(config))
        (target_root / "apm-hooks.json").write_text(json.dumps(sidecar))
        return target_root

    live_target = documents(project, live_package)
    replay_target = documents(scratch, cached_package)
    original_live = (live_target / "hooks.json").read_bytes()
    canonicalize_omp_hook_replay(
        scratch,
        project,
        [target],
        [target],
        {cached_package: live_package},
    )
    assert (live_target / "hooks.json").read_bytes() == original_live
    replayed = json.loads((replay_target / "hooks.json").read_text())
    assert replayed == json.loads(original_live)
    assert diff_scratch_against_project(scratch, project, LockFile(), [target]) == []

    changed = json.loads(original_live)
    changed["hooks"]["PreToolUse"][0]["hooks"][0]["apm"]["root"] = "/foreign/package"
    (live_target / "hooks.json").write_text(json.dumps(changed))
    findings = diff_scratch_against_project(scratch, project, LockFile(), [target])
    assert any(
        finding.path == ".omp/hooks.json" and finding.kind == "modified" for finding in findings
    )


def test_first_party_trust_does_not_create_dependency_status_from_ambient_code(tmp_path):
    from apm_cli.security.executables import ExecTrustContext

    _native(tmp_path)
    trust = ExecTrustContext(
        gate_enabled=True,
        org_deny_all=False,
        org_deny=frozenset(),
        org_require=frozenset(),
        org_recommend=frozenset(),
        org_enforce=frozenset(),
        org_bin_deny_all=False,
        org_bin_deny=frozenset(),
        project_allow={},
        project_deny={},
        user_allow={},
        user_deny={},
    )
    context = SimpleNamespace(
        exec_trust_ctx=trust,
        blocked_executables=[],
        package_exec_status={},
    )
    package = SimpleNamespace(install_path=tmp_path)
    assert (
        check_executable_approval(
            "_local",
            package,
            {},
            ctx=context,
            is_first_party=True,
        )
        == (True,) * 6
    )
    assert context.blocked_executables == []
    assert context.package_exec_status == {}
    assert check_executable_approval("_local", package, {}, ctx=context)[-1] is False
    assert context.blocked_executables
    assert context.package_exec_status["_local"] == "gated_pending_approval"


@pytest.mark.parametrize("directory", ["project", "project with spaces"])
def test_own_export_uses_stable_local_identity(tmp_path, directory):
    project = tmp_path / directory
    source = project / ".apm" / "extensions"
    _native(source)
    attested = {
        ".omp/extensions/_local/package.json": (source / "package.json", "_local"),
    }
    _require_attested_native_sources(project, attested, "omp")
