"""Audit replays recorded native roots rather than the current agent-dir override."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from apm_cli.core.deployment_ledger import DeploymentLedgerCodec
from apm_cli.core.deployment_state import (
    DeploymentLedger,
    DeploymentLocator,
    DeploymentRecord,
    LocatorKind,
)
from apm_cli.deps.lockfile import LockedDependency, LockFile
from apm_cli.install.audit_target_roots import external_replay_root
from apm_cli.install.cache_pin import verify_marker, write_marker
from apm_cli.install.drift import _build_package_info
from apm_cli.integration.hook_integrator import HookIntegrator
from apm_cli.integration.targets import KNOWN_TARGETS, resolve_audit_targets
from apm_cli.models.apm_package import build_installed_package_info
from apm_cli.models.validation import PackageType
from apm_cli.policy.ci_checks import DRIFT_SKIP_PREFIX, _check_drift
from apm_cli.utils.content_hash import compute_file_hash


def _git(repo: Path, *args: str) -> str:
    """Run real Git against *repo* without reading the developer's Git configuration."""
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=APM Test",
            "-c",
            "user.email=apm-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return completed.stdout.strip()


def _commit_package_source(origin: Path, index: int) -> str:
    """Commit one authoritative APM package (manifest + hook descriptor); return its HEAD."""
    descriptor = origin / ".apm" / "hooks" / "hooks.json"
    descriptor.parent.mkdir(parents=True)
    descriptor.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [{"type": "command", "command": f"printf native-{index}"}],
                        }
                    ]
                }
            }
        )
    )
    (origin / "apm.yml").write_text(f"name: package-{index}\nversion: 1.0.0\ntargets: [omp]\n")
    _git(origin, "init", "--quiet", "--initial-branch=main")
    _git(origin, "add", "--all")
    _git(origin, "commit", "--quiet", "-m", f"package-{index}")
    commit = _git(origin, "rev-parse", "HEAD")
    assert re.fullmatch(r"[0-9a-f]{40,64}", commit), commit
    return commit


def _install_recorded_hooks(tmp_path: Path, monkeypatch, count: int):
    home = tmp_path / "home"
    metadata = home / ".apm"
    metadata.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(metadata)
    modules = metadata / "apm_modules"
    lock = LockFile()
    records = {}
    roots = []
    for index in range(count):
        origin = tmp_path / "origin" / f"package-{index}"
        commit = _commit_package_source(origin, index)
        # A pinned remote dependency exactly as install records it: the lock carries
        # the real source commit and the cache holds that commit's tree plus its pin.
        dep = LockedDependency(
            repo_url=f"org/package-{index}",
            version="1.0.0",
            resolved_commit=commit,
            package_type="apm_package",
        )
        reference = dep.to_dependency_ref()
        source = reference.get_install_path(modules)
        _git(origin, "checkout-index", "--all", f"--prefix={source.as_posix()}/")
        installed = build_installed_package_info(reference, modules)
        assert installed is not None, "cached source must validate as an installed package"
        assert installed.package_type is PackageType.APM_PACKAGE
        # The same builder the replay uses, so install and replay share one
        # dependency identity, manifest identity and package type.
        info = _build_package_info(dep, source)
        root = tmp_path / f"previous-agent-{index}"
        monkeypatch.setenv("PI_CODING_AGENT_DIR", str(root))
        target = KNOWN_TARGETS["omp"].for_scope(user_scope=True)
        result = HookIntegrator().integrate_hooks_for_target(
            target,
            info,
            home,
            user_scope=True,
        )
        # Install writes the cache pin after integration (LockfileBuilder).
        write_marker(source, commit)
        verify_marker(source, commit)
        lock.add_dependency(dep)
        owner = dep.get_unique_key()
        for path in result.target_paths:
            # Older user installs used project scope labels, but retained an
            # explicit target, active owner, and persisted hash witness.
            locator = DeploymentLocator(
                kind=LocatorKind.PROJECT_RELATIVE,
                target="omp",
                value=str(path),
                runtime=None,
                scope="project",
            )
            records[locator.key] = DeploymentRecord(
                locator=locator,
                owners=(owner,),
                active_owner=owner,
                content_hash=compute_file_hash(path),
            )
        roots.append(root)
    DeploymentLedgerCodec.apply_to_lockfile(DeploymentLedger(records), lock)
    lock.write(metadata / "apm.lock.yaml")
    (metadata / "apm.yml").write_text("name: recorded-native-audit\nversion: 1.0.0\n")
    current_root = tmp_path / "new-agent-dir"
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(current_root))
    return metadata, lock, roots, current_root


def _record_real_replays(monkeypatch):
    """Observe real run_replay calls (no stub): each entry is (config, scratch_root)."""
    from apm_cli.install import drift

    real = drift.run_replay
    calls = []

    def observed(config, logger):
        scratch = real(config, logger)
        calls.append((config, scratch))
        return scratch

    monkeypatch.setattr(drift, "run_replay", observed)
    return calls


def _snapshot(root: Path):
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize("count", [1, 2])
@pytest.mark.parametrize("mutation", [None, "edited", "missing"])
def test_audit_replays_old_agent_roots_and_detects_owned_descriptor_drift(
    tmp_path,
    monkeypatch,
    count,
    mutation,
):
    metadata, lock, roots, current_root = _install_recorded_hooks(tmp_path, monkeypatch, count)
    replays = _record_real_replays(monkeypatch)
    changed_root = roots[-1]
    if mutation == "edited":
        descriptor = changed_root / "hooks.json"
        data = json.loads(descriptor.read_text())
        data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = "printf edited"
        descriptor.write_text(json.dumps(data))
    elif mutation == "missing":
        shutil.rmtree(changed_root)

    targets = resolve_audit_targets(metadata, user_scope=True, lockfile=lock)
    omp_targets = [target for target in targets if target.name == "omp"]
    assert {target.managed_deploy_root for target in omp_targets} == set(roots)
    assert len({external_replay_root(tmp_path / "scratch", target) for target in targets}) == count
    before = {root: _snapshot(root) for root in roots}
    result, findings = _check_drift(metadata, lock, cache_only=True)
    # The replay must have really run (not been skipped on a cache miss) and
    # produced a descriptor for every recorded root.
    assert DRIFT_SKIP_PREFIX not in result.message, result.message
    assert len(replays) == 1, result.message
    _config, scratch = replays[0]
    for target in omp_targets:
        assert (external_replay_root(scratch, target) / "hooks.json").is_file()
    if mutation is None:
        assert result.passed, result.message
        assert result.message == "no drift detected against lockfile"
        assert findings == []
    else:
        assert not result.passed, result.message
        assert result.message.startswith("drift detected"), result.message
        assert any(finding.path == str(changed_root / "hooks.json") for finding in findings)
        assert all(str(changed_root) in finding.path for finding in findings)
    assert {root: _snapshot(root) for root in roots} == before
    assert not current_root.exists()


def test_unattributed_absolute_runtime_suffix_does_not_redirect_audit(tmp_path, monkeypatch):
    metadata, lock, roots, current_root = _install_recorded_hooks(tmp_path, monkeypatch, 1)
    from dataclasses import replace

    records = {
        replace(record.locator, target="legacy").key: replace(
            record,
            locator=replace(record.locator, target="legacy"),
        )
        for record in lock.deployment_ledger.records.values()
    }
    DeploymentLedgerCodec.apply_to_lockfile(DeploymentLedger(records), lock)
    targets = resolve_audit_targets(metadata, user_scope=True, lockfile=lock)
    assert not any(target.managed_deploy_root in roots for target in targets)
    assert not current_root.exists()


def test_user_audit_replay_keeps_user_bridge_namespace(tmp_path, monkeypatch):
    from apm_cli.install.drift import CheckLogger, ReplayConfig, run_replay

    metadata, lock, _roots, current_root = _install_recorded_hooks(tmp_path, monkeypatch, 1)
    scratch = tmp_path / "scoped-replay"
    run_replay(
        ReplayConfig(
            project_root=metadata,
            lockfile_path=metadata / "apm.lock.yaml",
            scratch_root=scratch,
            cache_only=True,
            user_scope=True,
        ),
        CheckLogger(verbose=False),
    )
    targets = resolve_audit_targets(metadata, user_scope=True, lockfile=lock)
    replay_root = external_replay_root(scratch, targets[0])
    state = json.loads((replay_root / "apm-hooks-runtime.json").read_text())
    assert state["scope"] == "user"
    assert (replay_root / "extensions" / "apm-hooks-user" / "index.ts").is_file()
    assert not (replay_root / "extensions" / "apm-hooks-project").exists()
    assert not current_root.exists()
