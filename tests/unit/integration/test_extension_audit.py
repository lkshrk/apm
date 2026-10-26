"""Audit verifies ledger-owned native bundles and hook runtime as whole units."""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import replace
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace

import pytest

from apm_cli.core.deployment_ledger import DeploymentLedgerCodec
from apm_cli.core.deployment_state import (
    DeploymentLedger,
    DeploymentLocator,
    DeploymentRecord,
    LocatorKind,
)
from apm_cli.deps.lockfile import LockFile
from apm_cli.integration.extension_audit import audit_native_extension_ownership
from apm_cli.integration.extension_integrator import ExtensionIntegrator
from apm_cli.integration.omp_hook_integrator import OMP_HOOK_BRIDGES, OMP_HOOK_RUNTIME_STATE
from apm_cli.integration.targets import KNOWN_TARGETS
from apm_cli.policy.ci_checks import _check_content_integrity, _resolve_deployed_file_path
from apm_cli.utils.content_hash import compute_file_hash

OMP = KNOWN_TARGETS["omp"]
BUNDLE = ".omp/extensions/arbitrary-tools"


def _package(tmp_path: Path) -> Path:
    root = tmp_path / "arbitrary-tools"
    (root / "src").mkdir(parents=True)
    (root / "package.json").write_text(json.dumps({"omp": {"extensions": ["src/factory.ts"]}}))
    (root / "src/factory.ts").write_text("export default function(api) {}\n")
    (root / "assets").mkdir()
    (root / "assets/logo.png").write_bytes(b"\x89PNG\r\n\x00\x00binary")
    (root / "notes.txt").write_text("resource\n")
    # Package resources that merely resemble hook runtime artifacts.
    (root / "assets/apm-hooks-runtime.json").write_text('{"fixture": true}\n')
    (root / "fixtures/extensions/apm-hooks-project").mkdir(parents=True)
    (root / "fixtures/extensions/apm-hooks-project/index.ts").write_text("export {};\n")
    return root


def _lock(
    project: Path,
    paths,
    *,
    target: str = "omp",
    owner: str = ".",
    unhashed: frozenset[str] = frozenset(),
) -> LockFile:
    records = {}
    for path in paths:
        value = (
            path
            if isinstance(path, str)
            else (
                path.relative_to(project).as_posix()
                if path.is_relative_to(project)
                else path.as_posix()
            )
        )
        locator = DeploymentLocator(
            kind=LocatorKind.PROJECT_RELATIVE,
            target=target,
            value=value,
            runtime=None,
            scope="project",
        )
        records[locator.key] = DeploymentRecord(
            locator=locator,
            owners=(owner,),
            active_owner=owner,
            content_hash=(
                compute_file_hash(project / value)
                if (project / value).is_file() and Path(value).name not in unhashed
                else None
            ),
        )
    lock = LockFile()
    DeploymentLedgerCodec.apply_to_lockfile(DeploymentLedger(records), lock)
    return lock


def _install(tmp_path: Path, target=OMP):
    project = tmp_path / "project"
    result = ExtensionIntegrator().integrate_extensions_for_target(
        target,
        SimpleNamespace(install_path=_package(tmp_path)),
        project,
        package_name="arbitrary-tools",
        trust_extensions=True,
    )
    return project, result.target_paths


def _audit(project: Path, lock: LockFile, targets=(OMP,)):
    return audit_native_extension_ownership(
        project,
        lock,
        targets,
        lambda value: _resolve_deployed_file_path(value, project, targets),
    )


def test_clean_bundle_passes_and_scanner_sees_assets_as_coverage(tmp_path):
    project, paths = _install(tmp_path)
    lock = _lock(project, paths)
    assert _audit(project, lock) == ()
    check = _check_content_integrity(project, lock, (OMP,))
    assert check.passed, check.details
    assert not [entry for entry in check.coverage if entry.status == "incomplete"]


def _foreign_file(bundle: Path) -> None:
    (bundle / "foreign.txt").write_text("operator")


def _foreign_dir(bundle: Path) -> None:
    (bundle / "vendor/deep").mkdir(parents=True)
    (bundle / "vendor/deep/x.js").write_text("x")


def _foreign_symlink(bundle: Path) -> None:
    (bundle / "link").symlink_to(bundle.parent)


def _git_dir(bundle: Path) -> None:
    (bundle / ".git").mkdir()
    (bundle / ".git/HEAD").write_text("ref")


def _modified(bundle: Path) -> None:
    (bundle / "src/factory.ts").write_text("// edited\n")


def _missing(bundle: Path) -> None:
    (bundle / "notes.txt").unlink()


def _edited_receipt(bundle: Path) -> None:
    (bundle / ".apm-extension.json").write_text("{}\n")


def _payload_symlink(bundle: Path) -> None:
    (bundle / "notes.txt").unlink()
    (bundle / "notes.txt").symlink_to(bundle / "package.json")


@pytest.mark.parametrize(
    ("mutate", "fragment"),
    [
        (_foreign_file, "foreign foreign.txt"),
        (_foreign_dir, "foreign vendor/"),
        (_foreign_symlink, "foreign link/"),
        (_git_dir, "foreign .git/"),
        (_modified, "modified src/factory.ts"),
        (_missing, "missing notes.txt"),
        (_edited_receipt, "receipt edited"),
        (_payload_symlink, "symlink notes.txt"),
    ],
)
def test_damaged_bundle_yields_one_structured_failure(tmp_path, mutate, fragment):
    project, paths = _install(tmp_path)
    lock = _lock(project, paths)
    mutate(project / BUNDLE)
    failures = _audit(project, lock)
    assert [(failure.kind, failure.root) for failure in failures] == [("bundle", BUNDLE)]
    assert fragment in failures[0].detail()
    check = _check_content_integrity(project, lock, (OMP,))
    assert not check.passed
    assert len([detail for detail in check.details if detail.startswith("native-bundle:")]) == 1
    assert not [detail for detail in check.details if detail.startswith("incomplete-coverage")]


def test_payload_without_ledger_claim_is_unrecorded(tmp_path):
    project, paths = _install(tmp_path)
    lock = _lock(project, [path for path in paths if path.name != "notes.txt"])
    failures = _audit(project, lock)
    assert [failure.root for failure in failures] == [BUNDLE]
    assert "unrecorded notes.txt" in failures[0].detail()


def test_payload_claims_without_receipt_row_are_damaged(tmp_path):
    project, paths = _install(tmp_path)
    lock = _lock(project, [path for path in paths if path.name != ".apm-extension.json"])
    failures = _audit(project, lock)
    assert [failure.root for failure in failures] == [BUNDLE]
    assert "receipt not claimed by ledger" in failures[0].detail()


def _forbid_reads_below(monkeypatch, *roots: Path) -> list[str]:
    """Record every content read or listing aimed below *roots* (lexically)."""
    from apm_cli.integration import omp_hook_integrator

    seen: list[str] = []
    barred = tuple(roots)

    def _watch(label, original):
        def wrapper(first, *args, **kwargs):
            if any(Path(first).absolute().is_relative_to(root) for root in barred):
                seen.append(f"{label}: {first}")
            return original(first, *args, **kwargs)

        return wrapper

    for name in ("read_text", "read_bytes", "open", "iterdir", "rglob", "glob"):
        monkeypatch.setattr(Path, name, _watch(name, getattr(Path, name)))
    for name in ("walk",):
        monkeypatch.setattr(os, name, _watch(name, getattr(os, name)))
    monkeypatch.setattr(os, "scandir", _watch("scandir", os.scandir))
    monkeypatch.setattr(os, "listdir", _watch("listdir", os.listdir))
    monkeypatch.setattr(
        "apm_cli.utils.content_hash.compute_file_hash", _watch("hash", compute_file_hash)
    )
    monkeypatch.setattr(omp_hook_integrator, "compute_file_hash", _watch("hash", compute_file_hash))
    monkeypatch.setattr(
        ExtensionIntegrator, "_owned", staticmethod(_watch("owned", ExtensionIntegrator._owned))
    )
    return seen


def test_symlinked_bundle_root_fails_without_following_it(tmp_path, monkeypatch):
    project, paths = _install(tmp_path)
    lock = _lock(project, paths)
    bundle = project / BUNDLE
    moved = tmp_path / "moved"
    bundle.rename(moved)
    bundle.symlink_to(moved, target_is_directory=True)
    reads = _forbid_reads_below(monkeypatch, bundle, moved)
    failures = _audit(project, lock)
    assert [(failure.kind, failure.root) for failure in failures] == [("bundle", BUNDLE)]
    assert "symlinked root" in failures[0].detail()
    assert reads == []


def test_symlinked_ancestor_of_bundle_root_fails_at_the_bundle_root(tmp_path, monkeypatch):
    project, paths = _install(tmp_path)
    lock = _lock(project, paths)
    extensions = project / ".omp/extensions"
    moved = tmp_path / "moved-extensions"
    extensions.rename(moved)
    extensions.symlink_to(moved, target_is_directory=True)
    reads = _forbid_reads_below(monkeypatch, extensions, moved)
    failures = _audit(project, lock)
    assert [(failure.kind, failure.root) for failure in failures] == [("bundle", BUNDLE)]
    assert "symlinked root" in failures[0].detail()
    assert reads == []


def test_symlinked_runtime_root_fails_without_following_it(tmp_path, monkeypatch):
    project = tmp_path / "project"
    paths = _runtime(project)
    lock = _lock(project, paths)
    root = project / ".omp"
    moved = tmp_path / "moved-omp"
    root.rename(moved)
    root.symlink_to(moved, target_is_directory=True)
    reads = _forbid_reads_below(monkeypatch, root, moved)
    failures = _audit(project, lock)
    assert [(failure.kind, failure.root) for failure in failures] == [("runtime", ".omp")]
    assert "symlinked root" in failures[0].detail()
    assert reads == []


@pytest.mark.parametrize("kind", [LocatorKind.PROJECT_RELATIVE, LocatorKind.TARGET_RELATIVE])
def test_symlinked_external_bundle_root_is_never_read(tmp_path, monkeypatch, kind):
    custom = tmp_path / "previous-agent"
    target = replace(OMP, root_dir=custom.as_posix(), user_root_dir=custom.as_posix())
    project, paths = _install(tmp_path, target)
    records = {}
    for path in paths:
        value = (
            path.as_posix()
            if kind is LocatorKind.PROJECT_RELATIVE
            else path.relative_to(custom).as_posix()
        )
        locator = DeploymentLocator(
            kind=kind, target="omp", value=value, runtime=None, scope="project"
        )
        records[locator.key] = DeploymentRecord(
            locator=locator,
            owners=(".",),
            active_owner=".",
            content_hash=compute_file_hash(path),
        )
    lock = LockFile()
    DeploymentLedgerCodec.apply_to_lockfile(DeploymentLedger(records), lock)
    bundle = custom / "extensions/arbitrary-tools"
    moved = tmp_path / "moved"
    bundle.rename(moved)
    bundle.symlink_to(moved, target_is_directory=True)
    reads = _forbid_reads_below(monkeypatch, bundle, moved)
    failures = _audit(project, lock, (target,))
    assert [(failure.kind, failure.root) for failure in failures] == [("bundle", bundle.as_posix())]
    assert "symlinked root" in failures[0].detail()
    # The generic hash loop runs before the native audit and must not read through the link either.
    check = _check_content_integrity(project, lock, (target,))
    assert not check.passed
    assert reads == []


def test_absent_bundle_is_left_to_the_presence_check(tmp_path):
    project, paths = _install(tmp_path)
    lock = _lock(project, paths)
    shutil.rmtree(project / BUNDLE)
    assert _audit(project, lock) == ()


def test_unmanaged_ambient_siblings_are_never_inspected(tmp_path):
    project, paths = _install(tmp_path)
    lock = _lock(project, paths)
    ambient = project / ".omp/extensions/ambient"
    ambient.mkdir()
    (ambient / "index.ts").write_text("export default () => {};\n")
    (ambient / "stray.bin").write_bytes(b"\x00")
    (project / ".omp/extensions/mine.ts").write_text("export default () => {};\n")
    before = {p: p.read_bytes() for p in ambient.rglob("*") if p.is_file()}
    assert _audit(project, lock) == ()
    assert {p: p.read_bytes() for p in ambient.rglob("*") if p.is_file()} == before
    assert _check_content_integrity(project, lock, (OMP,)).passed


def test_historical_custom_root_is_verified_from_its_receipt_row(tmp_path):
    custom = tmp_path / "previous-agent"
    target = replace(OMP, root_dir=custom.as_posix(), user_root_dir=custom.as_posix())
    project, paths = _install(tmp_path, target)
    assert all(path.is_relative_to(custom) for path in paths)
    lock = _lock(project, paths)
    assert _audit(project, lock, (target,)) == ()
    (custom / "extensions/arbitrary-tools/foreign.txt").write_text("operator")
    failures = _audit(project, lock, (target,))
    assert [failure.root for failure in failures] == [
        (custom / "extensions/arbitrary-tools").resolve().as_posix()
    ]
    # Unattributed legacy rows never authorize a custom root.
    assert _audit(project, _lock(project, paths, target="legacy"), (target,)) == ()


def test_imperative_bundle_owner_rows_are_audited(tmp_path):
    project, paths = _install(tmp_path)
    lock = _lock(project, paths, owner="local-bundle")
    # The receipt names the package; the ledger names the imperative owner. Both are valid.
    assert _audit(project, lock) == ()
    (project / BUNDLE / "foreign.txt").write_text("operator")
    assert "foreign foreign.txt" in _audit(project, lock)[0].detail()


def test_bundle_resources_resembling_runtime_artifacts_are_not_runtime_roots(tmp_path):
    from apm_cli.integration.extension_roots import recorded_omp_roots

    project, paths = _install(tmp_path)
    lock = _lock(project, paths)
    assert any(path.name == OMP_HOOK_RUNTIME_STATE for path in paths)
    assert any(path.parent.name == "apm-hooks-project" for path in paths)
    assert _audit(project, lock) == ()
    assert recorded_omp_roots(lock, project) == {project / ".omp"}
    # A receipt row without a usable hash yields no root, yet its bundle's
    # resources still never invent historical roots.
    unhashed = _lock(project, paths, unhashed=frozenset({".apm-extension.json"}))
    assert recorded_omp_roots(unhashed, project) == set()
    _edited_receipt(project / BUNDLE)
    assert [(failure.kind, failure.root) for failure in _audit(project, lock)] == [
        ("bundle", BUNDLE)
    ]


@pytest.mark.parametrize("unhashed", [".apm-extension.json", "notes.txt"])
def test_claimed_bundle_files_without_ledger_hash_are_reported(tmp_path, unhashed):
    project, paths = _install(tmp_path)
    lock = _lock(project, paths, unhashed=frozenset({unhashed}))
    failures = _audit(project, lock)
    assert [failure.root for failure in failures] == [BUNDLE]
    assert "ledger hash" in failures[0].detail()


def _runtime(project: Path, scope: str = "project") -> list[Path]:
    root = project / ".omp"
    bridge = root / OMP_HOOK_BRIDGES[scope]
    bridge.parent.mkdir(parents=True)
    bridge.write_text(
        files("apm_cli.integration").joinpath("omp_hook_runtime.ts").read_text(encoding="utf-8")
    )
    state = root / OMP_HOOK_RUNTIME_STATE
    state.write_text(
        json.dumps(
            {"scope": scope, "bridgeHash": compute_file_hash(bridge), "configCreated": False}
        )
    )
    return [bridge, state]


def test_runtime_bridge_and_state_verify_without_touching_shared_hooks(tmp_path):
    project = tmp_path / "project"
    paths = _runtime(project)
    hooks = project / ".omp/hooks.json"
    hooks.write_text('{"hooks": {}}\n')
    lock = _lock(project, paths)
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (hooks, *paths)}
    assert _audit(project, lock) == ()
    assert {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (hooks, *paths)} == before


@pytest.mark.parametrize("damage", ["foreign-file", "edited-bridge", "foreign-state"])
def test_damaged_runtime_yields_one_structured_failure(tmp_path, damage):
    project = tmp_path / "project"
    bridge, state = _runtime(project)
    lock = _lock(project, [bridge, state])
    if damage == "foreign-file":
        (bridge.parent / "extra.ts").write_text("// foreign")
    elif damage == "edited-bridge":
        bridge.write_text("// edited")
    else:
        state.write_text('{"unrelated": true}')
    failures = _audit(project, lock)
    assert [(failure.kind, failure.root) for failure in failures] == [("runtime", ".omp")]
    check = _check_content_integrity(project, lock, (OMP,))
    assert not check.passed
    assert len([detail for detail in check.details if detail.startswith("native-runtime:")]) == 1


@pytest.mark.parametrize("unhashed", [OMP_HOOK_RUNTIME_STATE, "index.ts"])
def test_claimed_runtime_files_without_ledger_hash_are_reported(tmp_path, unhashed):
    project = tmp_path / "project"
    paths = _runtime(project)
    failures = _audit(project, _lock(project, paths, unhashed=frozenset({unhashed})))
    assert [(failure.kind, failure.root) for failure in failures] == [("runtime", ".omp")]
    assert "ledger hash missing or invalid" in failures[0].detail()
