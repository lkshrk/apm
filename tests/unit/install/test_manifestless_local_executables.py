"""Manifestless executable packages traverse the real local install pipeline."""

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


def _workspace(tmp_path, monkeypatch, user_scope):
    isolated = IsolatedApmEnvironment.create(tmp_path / "isolated", base_env=os.environ)
    for name, value in isolated.subprocess_env().items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("PI_CODING_AGENT_DIR", raising=False)
    monkeypatch.chdir(isolated.work_root)
    metadata = Path.home() / ".apm" if user_scope else isolated.work_root
    metadata.mkdir(parents=True, exist_ok=True)
    deployment_root = Path.home() if user_scope else isolated.work_root
    target_root = deployment_root / (".omp/agent" if user_scope else ".omp")
    return metadata, deployment_root, target_root


def _install(user_scope, target="omp"):
    args = ["install", "--target", target, "--no-policy", "--parallel-downloads", "0"]
    if user_scope:
        args.append("--global")
    return CliRunner().invoke(cli, args)


@pytest.mark.parametrize("user_scope", [False, True])
@pytest.mark.parametrize("kind", ["extensions", "hooks"])
def test_manifestless_local_executable_is_admitted_parked_then_deployed(
    tmp_path, monkeypatch, user_scope, kind
):
    metadata, deployment_root, target_root = _workspace(tmp_path, monkeypatch, user_scope)
    # Keep the authored source outside apm_modules: this must pass real local
    # directory admission, copying and resolver normalization, not a cache bypass.
    source = tmp_path / f"arbitrary-{kind}-source"
    resource = source / "assets/config.json"
    resource.parent.mkdir(parents=True)
    resource.write_text('{"value":"kept"}\n')
    if kind == "extensions":
        entry = source / "src/native.ts"
        entry.parent.mkdir()
        entry.write_text("export default api => {};\n")
        (source / "package.json").write_text(
            json.dumps(
                {
                    "name": "unrelated-native-package",
                    "version": "1.2.3",
                    "omp": {"extensions": ["src/native.ts"]},
                    "scripts": {
                        "postinstall": "node -e \"require('fs').writeFileSync('install-script-ran','unexpected')\""
                    },
                }
            )
        )
        expected_type = "extension_package"
    else:
        descriptor = source / "hooks/hooks.json"
        descriptor.parent.mkdir()
        descriptor.write_text(
            json.dumps(
                {
                    "hooks": {
                        "PreToolUse": [
                            {
                                "hooks": [
                                    {
                                        "type": "command",
                                        "command": 'node "${CLAUDE_PLUGIN_ROOT}/scripts/check.js"',
                                    }
                                ],
                            }
                        ]
                    }
                }
            )
        )
        script = source / "scripts/check.js"
        script.parent.mkdir()
        script.write_text(
            "require('fs').writeFileSync(process.env.PLUGIN_ROOT + '/hook-ran', 'unexpected');\n"
        )
        expected_type = "hook_package"
    reference = DependencyReference.parse(str(source))
    manifest = {
        "name": "manifestless-consumer",
        "version": "1.0.0",
        "targets": ["omp"],
        "dependencies": {"apm": [str(source)]},
        "executables": {"allow": {reference.to_canonical(): {kind: False}}},
    }
    manifest_path = metadata / "apm.yml"
    manifest_path.write_text(yaml.safe_dump(manifest))
    parked = _install(user_scope)
    assert parked.exit_code == 0, parked.output
    cached = reference.get_install_path(metadata / "apm_modules")
    assert cached.is_dir()
    assert (cached / "assets/config.json").read_bytes() == resource.read_bytes()
    assert not (source / "apm.yml").exists()
    assert not (cached / "apm.yml").exists()
    lock = LockFile.read(metadata / "apm.lock.yaml")
    record = lock.get_dependency(reference.get_unique_key())
    assert record.package_type == expected_type
    assert record.exec_status == "gated_pending_approval"
    assert record.deployed_files == []

    manifest["executables"]["allow"][reference.to_canonical()] = {kind: True}
    manifest_path.write_text(yaml.safe_dump(manifest))
    deployed = _install(user_scope)
    assert deployed.exit_code == 0, deployed.output
    lock = LockFile.read(metadata / "apm.lock.yaml")
    record = lock.get_dependency(reference.get_unique_key())
    assert record.package_type == expected_type
    assert record.exec_status == "deployed"
    assert record.deployed_files
    if kind == "extensions":
        entries = [path for path in record.deployed_files if path.endswith("/src/native.ts")]
        assert len(entries) == 1
        native = deployment_root / entries[0]
        assert native.is_relative_to(target_root / "extensions")
        assert native.read_bytes() == (source / "src/native.ts").read_bytes()
        assert (native.parent.parent / "assets/config.json").read_bytes() == resource.read_bytes()
    else:
        data = json.loads((target_root / "hooks.json").read_text())
        handler = data["hooks"]["PreToolUse"][0]["hooks"][0]
        assert handler["apm"]["root"] == str(cached.resolve())
        state = json.loads((target_root / "apm-hooks-runtime.json").read_text())
        assert state["scope"] == ("user" if user_scope else "project")
    repeated = _install(user_scope)
    assert repeated.exit_code == 0, repeated.output
    assert not (source / "apm.yml").exists()
    assert not (cached / "apm.yml").exists()
    assert not (source / "install-script-ran").exists()
    assert not (cached / "install-script-ran").exists()
    assert not (source / "hook-ran").exists()
    assert not (cached / "hook-ran").exists()


def test_arbitrary_local_javascript_repository_is_not_an_extension_package(tmp_path, monkeypatch):
    metadata, _deployment_root, target_root = _workspace(tmp_path, monkeypatch, False)
    source = tmp_path / "ordinary-javascript"
    source.mkdir()
    (source / "package.json").write_text(json.dumps({"name": "ordinary", "main": "index.js"}))
    (source / "index.js").write_text("export default () => {};\n")
    (metadata / "apm.yml").write_text(
        yaml.safe_dump(
            {
                "name": "consumer",
                "version": "1.0.0",
                "targets": ["omp"],
                "dependencies": {"apm": [str(source)]},
            }
        )
    )
    result = _install(False)
    assert result.exit_code != 0
    assert not (source / "apm.yml").exists()
    assert not list(target_root.rglob(".apm-extension.json"))


def test_local_native_missing_build_fails_without_building_or_portable_fallback(
    tmp_path, monkeypatch
):
    metadata, _deployment_root, target_root = _workspace(tmp_path, monkeypatch, False)
    source = tmp_path / "unbuilt-native"
    hooks = source / "hooks/hooks.json"
    hooks.parent.mkdir(parents=True)
    hooks.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [{"type": "command", "command": "printf forbidden-fallback"}],
                        }
                    ]
                }
            }
        )
    )
    (source / "package.json").write_text(
        json.dumps(
            {
                "omp": {"extensions": ["dist/native.js"]},
                "scripts": {
                    "postinstall": "node -e \"require('fs').mkdirSync('dist');require('fs').writeFileSync('dist/native.js','export default () => {};')\""
                },
            }
        )
    )
    reference = DependencyReference.parse(str(source))
    (metadata / "apm.yml").write_text(
        yaml.safe_dump(
            {
                "name": "consumer",
                "version": "1.0.0",
                "targets": ["omp"],
                "dependencies": {"apm": [str(source)]},
                "executables": {
                    "allow": {reference.to_canonical(): {"hooks": True, "extensions": True}}
                },
            }
        )
    )
    result = _install(False)
    assert result.exit_code != 0
    assert "declared native extension" in result.output.lower()
    cached = reference.get_install_path(metadata / "apm_modules")
    assert not (source / "dist/native.js").exists()
    assert not (cached / "dist/native.js").exists()
    assert not (target_root / "hooks.json").exists()
    assert not list(target_root.rglob(".apm-extension.json"))


def test_missing_native_build_does_not_block_manifestless_hooks_for_claude(tmp_path, monkeypatch):
    metadata, _deployment_root, native_root = _workspace(tmp_path, monkeypatch, False)
    source = tmp_path / "mixed-unbuilt-source"
    hooks = source / "hooks/hooks.json"
    hooks.parent.mkdir(parents=True)
    hooks.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [{"type": "command", "command": "printf claude-only"}],
                        }
                    ]
                }
            }
        )
    )
    (source / "package.json").write_text(json.dumps({"omp": {"extensions": ["build/missing.js"]}}))
    reference = DependencyReference.parse(str(source))
    (metadata / "apm.yml").write_text(
        yaml.safe_dump(
            {
                "name": "consumer",
                "version": "1.0.0",
                "targets": ["claude"],
                "dependencies": {"apm": [str(source)]},
                "executables": {"allow": {reference.to_canonical(): {"hooks": True}}},
            }
        )
    )
    result = _install(False, "claude")
    assert result.exit_code == 0, result.output
    settings = json.loads((metadata / ".claude/settings.json").read_text())
    assert settings["hooks"]["PreToolUse"]
    cached = reference.get_install_path(metadata / "apm_modules")
    assert not (cached / "apm.yml").exists()
    assert not (cached / "build/missing.js").exists()
    assert not (native_root / "hooks.json").exists()
    assert not list(native_root.rglob(".apm-extension.json"))


@pytest.mark.parametrize("user_scope", [False, True])
def test_manifestless_hooks_keep_legacy_default_trust_without_allowlist(
    tmp_path, monkeypatch, user_scope
):
    metadata, _deployment_root, target_root = _workspace(tmp_path, monkeypatch, user_scope)
    source = tmp_path / "default-hook-source"
    descriptor = source / "hooks/hooks.json"
    descriptor.parent.mkdir(parents=True)
    descriptor.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [{"type": "command", "command": "printf legacy-default"}],
                        }
                    ]
                }
            }
        )
    )
    reference = DependencyReference.parse(str(source))
    (metadata / "apm.yml").write_text(
        yaml.safe_dump(
            {
                "name": "consumer",
                "version": "1.0.0",
                "targets": ["omp"],
                "dependencies": {"apm": [str(source)]},
            }
        )
    )
    result = _install(user_scope)
    assert result.exit_code == 0, result.output
    native = json.loads((target_root / "hooks.json").read_text())
    assert native["hooks"]["PreToolUse"]
    lock = LockFile.read(metadata / "apm.lock.yaml")
    record = lock.get_dependency(reference.get_unique_key())
    assert record.exec_status is None
    assert record.deployed_files
    assert not (source / "apm.yml").exists()
