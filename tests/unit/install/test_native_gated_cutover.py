"""Native precedence is visible when its replacement is not yet approved."""

from __future__ import annotations

import json
import os

import yaml
from click.testing import CliRunner

from apm_cli.cli import cli
from apm_cli.deps.lockfile import LockFile
from apm_cli.models.dependency import DependencyReference
from tests.utils.isolated_apm_environment import IsolatedApmEnvironment


def test_gated_native_cutover_removes_portable_selection_and_explains_policy(tmp_path, monkeypatch):
    isolated = IsolatedApmEnvironment.create(tmp_path / "isolated", base_env=os.environ)
    for name, value in isolated.subprocess_env().items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("PI_CODING_AGENT_DIR", raising=False)
    project = isolated.work_root
    monkeypatch.chdir(project)
    source = tmp_path / "arbitrary-adapter"
    descriptor = source / ".apm/hooks/hooks.json"
    descriptor.parent.mkdir(parents=True)
    descriptor.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [{"type": "command", "command": "printf portable"}],
                        }
                    ]
                }
            }
        )
    )
    (source / "apm.yml").write_text("name: arbitrary-adapter\nversion: 1.0.0\n")
    reference = DependencyReference.parse(str(source))
    (project / "apm.yml").write_text(
        yaml.safe_dump(
            {
                "name": "consumer",
                "version": "1.0.0",
                "targets": ["omp"],
                "dependencies": {"apm": [str(source)]},
                "executables": {"allow": {reference.to_canonical(): {"hooks": True}}},
            }
        )
    )
    arguments = ["install", "--target", "omp", "--no-policy", "--parallel-downloads", "0"]
    first = CliRunner().invoke(cli, arguments)
    assert first.exit_code == 0, first.output
    native_config = project / ".omp/hooks.json"
    assert json.loads(native_config.read_text())["hooks"]["PreToolUse"]

    # Updating the package must not run its newly changed portable handlers as
    # a fallback for the independently unapproved native replacement.
    descriptor.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [{"type": "command", "command": "printf updated-portable"}],
                        }
                    ]
                }
            }
        )
    )
    (source / "package.json").write_text(json.dumps({"omp": {"extensions": ["native.ts"]}}))
    (source / "native.ts").write_text("export default api => {};\n")
    second = CliRunner().invoke(cli, arguments)
    assert second.exit_code == 0, second.output
    remaining = json.loads(native_config.read_text()) if native_config.exists() else {}
    assert not remaining.get("hooks", {}).get("PreToolUse")
    assert not list((project / ".omp/extensions").rglob("native.ts"))
    lockfile = LockFile.read(project / "apm.lock.yaml")
    assert (
        lockfile.get_dependency(reference.get_unique_key()).exec_status == "gated_pending_approval"
    )
    visible = second.output.lower()
    assert all(term in visible for term in ("native", "portable", "precedence", "approval"))
