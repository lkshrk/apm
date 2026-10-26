"""Real CLI audit treats native payloads as assets while enforcing their ownership."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from apm_cli.cli import cli
from apm_cli.deps.lockfile import LockFile
from apm_cli.models.dependency import DependencyReference
from tests.utils.isolated_apm_environment import IsolatedApmEnvironment


@pytest.fixture(autouse=True)
def _reset_console_state():
    """Do not leak JSON-mode console routing into later logger tests."""
    from apm_cli.utils.console import _reset_console

    yield
    _reset_console()


def _installed_payload(tmp_path, monkeypatch, user_scope):
    isolated = IsolatedApmEnvironment.create(tmp_path / "isolated", base_env=os.environ)
    for name, value in isolated.subprocess_env().items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("PI_CODING_AGENT_DIR", raising=False)
    monkeypatch.chdir(isolated.work_root)
    metadata = Path.home() / ".apm" if user_scope else isolated.work_root
    metadata.mkdir(parents=True, exist_ok=True)
    deployment_root = Path.home() if user_scope else isolated.work_root
    target_root = deployment_root / (".omp/agent" if user_scope else ".omp")
    ambient = target_root / "extensions/manual.ts"
    ambient.parent.mkdir(parents=True)
    ambient.write_text("export default api => {};\n")

    native_source = tmp_path / "arbitrary-native-payload"
    files = {
        "package.json": json.dumps(
            {"name": "arbitrary-native-payload", "omp": {"extensions": ["src/native.mjs"]}}
        ).encode(),
        "src/native.mjs": b"export default api => {};\n",
        "checks/resource.sh": b"#!/bin/sh\nprintf 'asset only'\n",
        "support/helper.mjs": b"export const value = 7;\n",
        "assets/message.txt": b"ordinary runtime resource\n",
        "assets/icon.png": b"\x89PNG\r\n\x1a\n\x00binary fixture",
        "assets/apm-hooks-runtime.json": b'{"purpose":"ordinary package resource"}\n',
        "fixtures/extensions/apm-hooks-project/index.ts": b"export const fixture = true;\n",
    }
    for relative, data in files.items():
        path = native_source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    hook_source = tmp_path / "unrelated-portable-hooks"
    descriptor = hook_source / "hooks/hooks.json"
    descriptor.parent.mkdir(parents=True)
    descriptor.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [{"type": "command", "command": "printf audit-hook"}],
                        }
                    ]
                }
            }
        )
    )
    native_ref = DependencyReference.parse(str(native_source))
    hook_ref = DependencyReference.parse(str(hook_source))
    (metadata / "apm.yml").write_text(
        yaml.safe_dump(
            {
                "name": "native-audit-consumer",
                "version": "1.0.0",
                "targets": ["omp"],
                "dependencies": {"apm": [str(native_source), str(hook_source)]},
                "executables": {
                    "allow": {
                        native_ref.to_canonical(): {"extensions": True},
                        hook_ref.to_canonical(): {"hooks": True},
                    }
                },
            }
        )
    )
    arguments = ["install", "--target", "omp", "--no-policy", "--parallel-downloads", "0"]
    if user_scope:
        arguments.append("--global")
    installed = CliRunner().invoke(cli, arguments)
    assert installed.exit_code == 0, installed.output
    lock = LockFile.read(metadata / "apm.lock.yaml")
    dependency = lock.get_dependency(native_ref.get_unique_key())
    entries = [value for value in dependency.deployed_files if value.endswith("/src/native.mjs")]
    assert len(entries) == 1
    bundle = (deployment_root / entries[0]).parent.parent
    for relative in files:
        if relative != "package.json":
            assert (bundle / relative).read_bytes() == files[relative]
    assert (bundle / ".apm-extension.json").is_file()
    monkeypatch.chdir(metadata)
    return bundle, target_root, ambient, files


def _audit():
    result = CliRunner().invoke(
        cli, ["audit", "--ci", "--no-policy", "--no-fail-fast", "--format", "json"]
    )
    assert result.stdout, (
        f"audit returned no JSON: output={result.output!r}, exception={result.exception!r}"
    )
    document = json.loads(result.stdout)
    checks = {check["name"]: check for check in document["checks"]}
    return result, document, checks


@pytest.mark.parametrize("user_scope", [False, True])
def test_native_binary_and_code_resources_pass_real_cli_audit(tmp_path, monkeypatch, user_scope):
    bundle, target_root, ambient, files = _installed_payload(tmp_path, monkeypatch, user_scope)
    result, document, checks = _audit()
    assert result.exit_code == 0, result.output
    assert document["passed"] is True
    integrity = checks["content-integrity"]
    assert integrity["passed"] is True
    inventory = integrity["primitive_coverage"]
    for suffix in (
        "checks/resource.sh",
        "support/helper.mjs",
        "assets/message.txt",
        "apm-hooks-runtime.json",
    ):
        entries = [entry for entry in inventory if entry["file"].endswith(suffix)]
        assert entries and all(entry["status"] == "checked" for entry in entries)
        assert all(entry["strippable"] is False for entry in entries)
    binary = [entry for entry in inventory if entry["file"].endswith("assets/icon.png")]
    assert binary and all(entry["status"] == "not-applicable" for entry in binary)
    assert not any(entry["status"] == "incomplete" for entry in inventory)
    for relative, data in files.items():
        if relative != "package.json":
            assert (bundle / relative).read_bytes() == data
    assert ambient.read_text() == "export default api => {};\n"
    assert (target_root / "hooks.json").is_file()


@pytest.mark.parametrize("user_scope", [False, True])
@pytest.mark.parametrize("mutation", ["edited", "missing", "foreign", "unicode"])
def test_real_cli_audit_rejects_damaged_or_foreign_native_payload(
    tmp_path, monkeypatch, user_scope, mutation
):
    bundle, _target_root, ambient, _files = _installed_payload(tmp_path, monkeypatch, user_scope)
    changed = bundle / "checks/resource.sh"
    if mutation == "missing":
        changed.unlink()
    elif mutation == "foreign":
        (bundle / "foreign.mjs").write_text("export default api => {};\n")
    elif mutation == "unicode":
        changed.write_text("#!/bin/sh\n# hidden \u202e control\n")
    else:
        changed.write_text("#!/bin/sh\nprintf 'operator edit'\n")
    before = {
        path.relative_to(bundle).as_posix(): path.read_bytes()
        for path in bundle.rglob("*")
        if path.is_file()
    }
    result, document, checks = _audit()
    assert result.exit_code != 0
    assert document["passed"] is False
    integrity = checks["content-integrity"]
    assert integrity["passed"] is False
    assert not any(
        "unsupported recognized primitive format" in detail
        for detail in integrity.get("details", [])
    )
    if mutation == "unicode":
        assert any(
            detail.startswith("unicode:") and "resource.sh" in detail
            for detail in integrity["details"]
        )
    assert {
        path.relative_to(bundle).as_posix(): path.read_bytes()
        for path in bundle.rglob("*")
        if path.is_file()
    } == before
    assert ambient.read_text() == "export default api => {};\n"


@pytest.mark.parametrize("user_scope", [False, True])
def test_real_cli_audit_rejects_foreign_files_in_owned_hook_runtime(
    tmp_path, monkeypatch, user_scope
):
    _bundle, target_root, ambient, _files = _installed_payload(tmp_path, monkeypatch, user_scope)
    runtime = target_root / "extensions" / ("apm-hooks-user" if user_scope else "apm-hooks-project")
    (runtime / "package.json").write_text(json.dumps({"omp": {"extensions": ["shadow.ts"]}}))
    (runtime / "shadow.ts").write_text("export default api => {};\n")
    before = {path.name: path.read_bytes() for path in runtime.iterdir() if path.is_file()}
    result, document, checks = _audit()
    assert result.exit_code != 0
    assert document["passed"] is False
    assert checks["content-integrity"]["passed"] is False
    assert {path.name: path.read_bytes() for path in runtime.iterdir() if path.is_file()} == before
    assert ambient.read_text() == "export default api => {};\n"


def test_real_cli_audit_reports_hook_contract_replay_failure_as_json(tmp_path, monkeypatch):
    isolated = IsolatedApmEnvironment.create(tmp_path / "isolated", base_env=os.environ)
    for name, value in isolated.subprocess_env().items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("PI_CODING_AGENT_DIR", raising=False)
    project = isolated.work_root
    monkeypatch.chdir(project)
    source = tmp_path / "claude-permission-hooks"
    descriptor = source / "hooks/hooks.json"
    descriptor.parent.mkdir(parents=True)
    descriptor.write_text(
        json.dumps(
            {
                "hooks": {
                    "PermissionRequest": [
                        {
                            "hooks": [{"type": "command", "command": "printf permission"}],
                        }
                    ]
                }
            }
        )
    )
    reference = DependencyReference.parse(str(source))
    manifest = {
        "name": "replay-consumer",
        "version": "1.0.0",
        "targets": ["claude"],
        "dependencies": {"apm": [str(source)]},
        "executables": {"allow": {reference.to_canonical(): {"hooks": True}}},
    }
    manifest_path = project / "apm.yml"
    manifest_path.write_text(yaml.safe_dump(manifest))
    installed = CliRunner().invoke(
        cli, ["install", "--target", "claude", "--no-policy", "--parallel-downloads", "0"]
    )
    assert installed.exit_code == 0, installed.output
    prior_config = (project / ".claude/settings.json").read_bytes()
    manifest["targets"] = ["omp"]
    manifest_path.write_text(yaml.safe_dump(manifest))
    result, document, checks = _audit()
    assert result.exit_code != 0
    assert document["passed"] is False
    assert checks["drift"]["passed"] is False
    assert "blocked" in checks["drift"]["message"].lower()
    assert "permission" in checks["drift"]["message"].lower()
    assert (project / ".claude/settings.json").read_bytes() == prior_config
    assert not (project / ".omp/hooks.json").exists()
