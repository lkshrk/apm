import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from apm_cli.commands.targets import targets
from apm_cli.core.errors import AmbiguousHarnessError
from apm_cli.core.target_detection import detect_signals, detect_target, resolve_targets
from apm_cli.integration.skill_integrator import SkillIntegrator
from apm_cli.integration.targets import (
    KNOWN_TARGETS,
    active_targets,
    active_targets_user_scope,
    apply_legacy_skill_paths,
)
from apm_cli.models.apm_package import APMPackage, PackageInfo, PackageType


def test_hermes_listed_when_inactive(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(targets, ["--json"])
    assert result.exit_code == 0, result.output
    row = next(row for row in json.loads(result.output) if row["target"] == "hermes")
    assert row == {
        "target": "hermes",
        "status": "inactive",
        "source": None,
        "deploy_dir": ".agents/",
        "needs": ".hermes/",
    }


def test_hermes_directory_detection(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".hermes").mkdir()
    assert detect_target(tmp_path) == ("hermes", "detected .hermes/ folder")
    assert resolve_targets(tmp_path).targets == ["hermes"]
    assert [p.name for p in active_targets(tmp_path)] == ["hermes"]
    result = CliRunner().invoke(targets)
    assert result.exit_code == 0, result.output
    row = next(line for line in result.output.splitlines() if "hermes" in line)
    assert "inactive" not in row
    assert ".hermes/" in row
    assert ".agents/" in row


@pytest.mark.parametrize("marker", [".hermes", "AGENTS.md", "SOUL.md", ".agents"])
def test_shared_context_and_files_do_not_activate_hermes(tmp_path, marker):
    path = tmp_path / marker
    if marker == ".agents":
        path.mkdir()
    else:
        path.write_text("context", encoding="utf-8")
    assert not any(s.target == "hermes" for s in detect_signals(tmp_path))
    assert "hermes" not in [p.name for p in active_targets(tmp_path)]


def test_hermes_multiple_targets_require_selection(tmp_path):
    (tmp_path / ".hermes").mkdir()
    (tmp_path / ".claude").mkdir()
    with pytest.raises(AmbiguousHarnessError):
        resolve_targets(tmp_path)
    assert resolve_targets(tmp_path, flag="hermes").targets == ["hermes"]


@pytest.mark.parametrize("user_scope", [False, True])
@pytest.mark.parametrize("legacy", [False, True])
def test_hermes_skill_deployment(tmp_path, monkeypatch, user_scope, legacy):
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    (tmp_path / ".hermes").mkdir()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    content = "---\nname: sample\ndescription: Sample skill\n---\n\nFollow this procedure.\n"
    (package_dir / "SKILL.md").write_text(content, encoding="utf-8")
    package = PackageInfo(
        package=APMPackage(name="sample", version="1.0.0", package_path=package_dir),
        install_path=package_dir,
        package_type=PackageType.CLAUDE_SKILL,
    )
    raw = active_targets_user_scope() if user_scope else active_targets(tmp_path)
    profiles = [p.for_scope(user_scope=user_scope) for p in raw]
    if legacy:
        profiles = apply_legacy_skill_paths(profiles)
    assert [p.name for p in profiles] == ["hermes"]
    result = SkillIntegrator().integrate_package_skill(package, tmp_path, targets=profiles)
    assert result.skill_created
    root = ".hermes" if user_scope else ".agents"
    deployed = list((tmp_path / root / "skills").glob("*/SKILL.md"))
    assert len(deployed) == 1
    assert "Follow this procedure." in deployed[0].read_text(encoding="utf-8")
    assert set(KNOWN_TARGETS["hermes"].primitives) == {"skills"}
