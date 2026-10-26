"""Native retarget/prune cleanup preserves or removes whole owned bundles."""

import json
from types import SimpleNamespace

import pytest

from apm_cli.core.deployment_state import (
    DeploymentLedger,
    DeploymentLocator,
    DeploymentRecord,
    LocatorKind,
)
from apm_cli.deps.lockfile import LockFile
from apm_cli.integration.cleanup import remove_stale_deployed_files
from apm_cli.integration.extension_integrator import RECEIPT_FILENAME, ExtensionIntegrator
from apm_cli.integration.extension_roots import recorded_omp_roots
from apm_cli.integration.targets import KNOWN_TARGETS
from apm_cli.utils.content_hash import compute_file_hash
from apm_cli.utils.diagnostics import DiagnosticCollector
from apm_cli.utils.paths import portable_relpath


@pytest.fixture
def installed_bundle(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "package.json").write_text(json.dumps({"omp": {"extensions": ["index.ts"]}}))
    (source / "index.ts").write_text("export default function(api) {}\n")
    (source / "assets").mkdir()
    (source / "assets/data.json").write_text('{"resource": true}\n')
    project = tmp_path / "project"
    target = KNOWN_TARGETS["omp"]
    integrator = ExtensionIntegrator()
    result = integrator.integrate_extensions_for_target(
        target,
        SimpleNamespace(install_path=source),
        project,
        package_name="fixture",
        trust_extensions=True,
    )
    hashes = {
        portable_relpath(path, project): compute_file_hash(path) for path in result.target_paths
    }
    return source, project, target, project / ".omp/extensions/fixture", hashes


def cleanup(
    project, target, hashes, *, selected=None, prune=False, user_scope=False, prior_lockfile=None
):
    return remove_stale_deployed_files(
        list(hashes) if selected is None else selected,
        project,
        dep_key="fixture",
        targets=[target],
        diagnostics=DiagnosticCollector(verbose=False),
        recorded_hashes=hashes,
        failed_path_retained=not prune,
        user_scope=user_scope,
        prior_lockfile=prior_lockfile,
    )


@pytest.mark.parametrize("prune", [False, True], ids=["retarget", "prune"])
def test_complete_owned_bundle_is_removed(installed_bundle, prune):
    _, project, target, root, hashes = installed_bundle
    result = cleanup(project, target, hashes, prune=prune)
    assert set(result.deleted) == set(hashes)
    assert not result.retained
    assert not root.exists()


@pytest.mark.parametrize("prune", [False, True], ids=["retarget", "prune"])
@pytest.mark.parametrize(
    "mutation", ["foreign", "edited", "receipt", "missing-receipt", "symlink", "directory-symlink"]
)
def test_changed_bundle_is_preserved_whole(installed_bundle, tmp_path, mutation, prune):
    _, project, target, root, hashes = installed_bundle
    if mutation == "foreign":
        (root / "operator.txt").write_text("keep this")
    elif mutation == "edited":
        (root / "assets/data.json").write_text("operator edit")
    elif mutation == "receipt":
        receipt = root / RECEIPT_FILENAME
        data = json.loads(receipt.read_text())
        data["owner"] = "another-owner"
        receipt.write_text(json.dumps(data))
    elif mutation == "missing-receipt":
        (root / RECEIPT_FILENAME).unlink()
    elif mutation == "symlink":
        outside = tmp_path / "outside.txt"
        outside.write_text("operator data")
        (root / "operator-link").symlink_to(outside)
    else:
        outside = tmp_path / "outside-dir"
        outside.mkdir()
        (outside / "data.txt").write_text("operator data")
        (root / "assets").rename(root / "saved-assets")
        (root / "assets").symlink_to(outside, target_is_directory=True)
    before = {
        path: path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    result = cleanup(project, target, hashes, prune=prune)
    assert not result.deleted
    assert set(result.retained) == set(hashes)
    assert root.is_dir()
    assert all(path.read_bytes() == data for path, data in before.items())
    if mutation == "symlink":
        assert (root / "operator-link").is_symlink()
        assert outside.read_text() == "operator data"
    if mutation == "directory-symlink":
        assert (root / "assets").is_symlink()
        assert (outside / "data.txt").read_text() == "operator data"


@pytest.mark.parametrize("selected_kind", ["asset", "receipt", "without-receipt"])
def test_partial_selection_never_dismantles_bundle(installed_bundle, selected_kind):
    _, project, target, _, hashes = installed_bundle
    if selected_kind == "asset":
        selected = [path for path in hashes if path.endswith("data.json")]
    elif selected_kind == "receipt":
        selected = [path for path in hashes if path.endswith(RECEIPT_FILENAME)]
    else:
        selected = [path for path in hashes if not path.endswith(RECEIPT_FILENAME)]
    result = cleanup(project, target, hashes, selected=selected)
    assert not result.deleted
    assert set(result.retained) == set(selected)
    assert all(compute_file_hash(project / path) == digest for path, digest in hashes.items())


def test_missing_lock_hash_does_not_enable_legacy_per_file_cleanup(installed_bundle):
    _, project, target, _, hashes = installed_bundle
    result = cleanup(project, target, {}, selected=list(hashes))
    assert not result.deleted
    assert set(result.retained) == set(hashes)
    assert all((project / path).exists() for path in hashes)


def test_source_update_stale_rows_cannot_remove_new_bundle(installed_bundle):
    source, project, target, root, old_hashes = installed_bundle
    (source / "assets/data.json").unlink()
    (source / "assets/new.json").write_text('{"new": true}\n')
    (source / "index.ts").write_text(
        "export default function(api) { api.registerFlag('new', {}); }\n"
    )
    result = ExtensionIntegrator().integrate_extensions_for_target(
        target,
        SimpleNamespace(install_path=source),
        project,
        package_name="fixture",
        trust_extensions=True,
        managed_files=set(old_hashes),
    )
    new_hashes = {
        portable_relpath(path, project): compute_file_hash(path) for path in result.target_paths
    }
    stale = set(old_hashes) - set(new_hashes)
    absent = cleanup(project, target, old_hashes, selected=stale)
    assert not absent.deleted
    assert not absent.retained
    # A stale full-group request must also fail closed against the old receipt.
    retained = cleanup(project, target, old_hashes)
    assert not retained.deleted
    assert set(retained.retained) == set(old_hashes)
    assert all(compute_file_hash(project / path) == digest for path, digest in new_hashes.items())
    assert (root / "assets/new.json").is_file()


@pytest.mark.parametrize("custom_root", [None, "custom-agent", "home/custom-agent"])
def test_user_scope_bundle_uses_resolved_target_root(
    installed_bundle, tmp_path, monkeypatch, custom_root
):
    source, _, _, _, _ = installed_bundle
    if custom_root:
        monkeypatch.setenv("PI_CODING_AGENT_DIR", str(tmp_path / custom_root))
    else:
        monkeypatch.delenv("PI_CODING_AGENT_DIR", raising=False)
    target = KNOWN_TARGETS["omp"].for_scope(user_scope=True)
    project = tmp_path / "home"
    result = ExtensionIntegrator().integrate_extensions_for_target(
        target,
        SimpleNamespace(install_path=source),
        project,
        package_name="fixture",
        trust_extensions=True,
    )
    hashes = {
        portable_relpath(path, project): compute_file_hash(path) for path in result.target_paths
    }
    removed = cleanup(project, target, hashes, prune=True, user_scope=True)
    assert set(removed.deleted) == set(hashes)
    assert not removed.retained
    assert not (project / target.root_dir / "extensions/fixture").exists()


@pytest.mark.parametrize("bridge", ["apm-hooks-project", "apm-hooks-user"])
def test_shared_hook_bridge_is_left_to_merged_hook_cleanup(tmp_path, bridge):
    target = KNOWN_TARGETS["omp"]
    paths = [f".omp/extensions/{bridge}/index.ts", ".omp/apm-hooks-runtime.json"]
    for relative in paths:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("shared by another installed package")
    hashes = {relative: compute_file_hash(tmp_path / relative) for relative in paths}
    result = cleanup(tmp_path, target, hashes, prune=True)
    assert not result.deleted
    assert set(result.retained) == set(paths)
    assert all(
        (tmp_path / relative).read_text() == "shared by another installed package"
        for relative in paths
    )


def test_missing_entire_bundle_is_already_clean(installed_bundle):
    _, project, target, root, hashes = installed_bundle
    for relative in hashes:
        (project / relative).unlink()
    (root / "assets").rmdir()
    root.rmdir()
    result = cleanup(project, target, hashes, prune=True)
    assert not result.deleted
    assert not result.retained


def test_modified_receipt_cannot_reauthorize_edited_payload(installed_bundle):
    _, project, target, root, hashes = installed_bundle
    payload = root / "index.ts"
    payload.write_text("export default function(operator) {}\n")
    receipt = root / RECEIPT_FILENAME
    data = json.loads(receipt.read_text())
    data["files"]["index.ts"] = compute_file_hash(payload).removeprefix("sha256:")
    receipt.write_text(json.dumps(data))
    result = cleanup(project, target, hashes, prune=True)
    assert not result.deleted
    assert set(result.retained) == set(hashes)
    assert all((project / relative).is_file() for relative in hashes)


def native_lockfile(hashes, *, owner="fixture", target="omp"):
    records = {}
    for path, digest in hashes.items():
        locator = DeploymentLocator(LocatorKind.PROJECT_RELATIVE, target, path, None, "project")
        records[locator.key] = DeploymentRecord(locator, (owner,), owner, digest)
    return LockFile(deployment_ledger=DeploymentLedger(records))


@pytest.fixture
def prior_native_bundle(installed_bundle, tmp_path, monkeypatch):
    source, project, _, _, _ = installed_bundle
    old_root = tmp_path / "previous-agent"
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(old_root))
    old_target = KNOWN_TARGETS["omp"].for_scope(user_scope=True)
    deployed = ExtensionIntegrator().integrate_extensions_for_target(
        old_target,
        SimpleNamespace(install_path=source),
        project,
        package_name="fixture",
        trust_extensions=True,
    )
    hashes = {
        portable_relpath(path, project): compute_file_hash(path) for path in deployed.target_paths
    }
    lockfile = native_lockfile(hashes)
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(tmp_path / "new-agent"))
    current = KNOWN_TARGETS["omp"].for_scope(user_scope=True)
    return project, old_root, hashes, lockfile, current


@pytest.mark.parametrize("prune", [False, True], ids=["retarget", "prune"])
def test_previous_agent_directory_cleanup_uses_recorded_owner(prior_native_bundle, prune):
    project, old_root, hashes, lockfile, current = prior_native_bundle
    result = cleanup(
        project, current, hashes, prior_lockfile=lockfile, prune=prune, user_scope=True
    )
    assert set(result.deleted) == set(hashes)
    assert not result.retained
    assert not (old_root / "extensions/fixture").exists()


@pytest.mark.parametrize(
    "mutation", ["receipt", "payload", "foreign", "symlink", "missing-receipt"]
)
def test_previous_agent_root_keeps_modified_bundle_visible_and_intact(
    prior_native_bundle, mutation
):
    project, old_root, hashes, lockfile, current = prior_native_bundle
    root = old_root / "extensions/fixture"
    if mutation == "receipt":
        (root / RECEIPT_FILENAME).write_text("{}")
    elif mutation == "payload":
        (root / "index.ts").write_text("operator code")
    elif mutation == "foreign":
        (root / "operator.txt").write_text("operator data")
    elif mutation == "symlink":
        (root / "index.ts").unlink()
        (root / "index.ts").symlink_to(root / "assets/data.json")
    else:
        (root / RECEIPT_FILENAME).unlink()
    assert recorded_omp_roots(lockfile, project, dependency_keys={"fixture"}) == {old_root}
    result = cleanup(project, current, hashes, prior_lockfile=lockfile, user_scope=True)
    assert not result.deleted
    assert set(result.retained) == set(hashes)
    assert (root / "assets/data.json").is_file()
    assert (root / "package.json").is_file()


@pytest.mark.parametrize(
    "untrusted", ["missing-ledger", "wrong-owner", "wrong-target", "missing-hash"]
)
def test_custom_root_suffix_and_hashes_alone_do_not_authorize_cleanup(
    prior_native_bundle, untrusted
):
    project, old_root, hashes, _, current = prior_native_bundle
    if untrusted == "missing-ledger":
        lockfile = None
    elif untrusted == "wrong-owner":
        lockfile = native_lockfile(hashes, owner="other")
    elif untrusted == "wrong-target":
        lockfile = native_lockfile(hashes, target="codex")
    else:
        lockfile = native_lockfile({path: None for path in hashes})
    assert recorded_omp_roots(lockfile, project, dependency_keys={"fixture"}) == set()
    result = cleanup(project, current, hashes, prior_lockfile=lockfile, user_scope=True)
    assert not result.deleted
    assert set(result.retained) == set(hashes)
    assert (old_root / "extensions/fixture/index.ts").is_file()


def test_previous_agent_root_partial_bundle_selection_is_preserved(prior_native_bundle):
    project, _, hashes, lockfile, current = prior_native_bundle
    selected = [path for path in hashes if path.endswith("index.ts")]
    result = cleanup(
        project, current, hashes, selected=selected, prior_lockfile=lockfile, user_scope=True
    )
    assert not result.deleted
    assert result.retained == selected
    assert all(compute_file_hash(project / path) == digest for path, digest in hashes.items())


def test_previous_agent_root_missing_bundle_stays_discoverable(prior_native_bundle):
    project, old_root, hashes, lockfile, current = prior_native_bundle
    for path in hashes:
        (project / path).unlink()
    assert recorded_omp_roots(lockfile, project) == {old_root}
    result = cleanup(project, current, hashes, prior_lockfile=lockfile, user_scope=True)
    assert not result.deleted
    assert not result.retained


@pytest.mark.parametrize(
    "artifact",
    [
        "apm-hooks-runtime.json",
        "extensions/apm-hooks-project/index.ts",
        "extensions/apm-hooks-user/index.ts",
    ],
)
def test_shared_hook_prior_roots_are_attributed_without_reading_disk(tmp_path, artifact):
    project = tmp_path / "project"
    old_root = tmp_path / "old-agent"
    path = (old_root / artifact).as_posix()
    lockfile = native_lockfile({path: "sha256:" + "a" * 64})
    assert recorded_omp_roots(lockfile, project, dependency_keys={"fixture"}) == {old_root}
    assert recorded_omp_roots(lockfile, project, dependency_keys={"other"}) == set()
    assert not old_root.exists()


def test_prior_root_discovery_rejects_traversal_and_unattributed_suffixes(tmp_path):
    hashes = {
        "../outside/extensions/fixture/.apm-extension.json": "sha256:" + "a" * 64,
        "arbitrary/.apm-extension.json": "sha256:" + "b" * 64,
    }
    assert recorded_omp_roots(native_lockfile(hashes), tmp_path) == set()
