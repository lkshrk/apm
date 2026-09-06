import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from apm_cli.commands.targets import targets
from apm_cli.compilation.agents_compiler import AgentsCompiler, CompilationConfig
from apm_cli.core.target_detection import detect_signals, detect_target
from apm_cli.integration.skill_integrator import copy_skill_to_target
from apm_cli.integration.targets import KNOWN_TARGETS, active_targets, resolve_targets
from apm_cli.models.apm_package import APMPackage, PackageInfo, PackageType


def test_hermes_directory_activates_and_is_listed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".hermes").mkdir()
    assert detect_target(tmp_path)[0] == "hermes"
    assert [s.target for s in detect_signals(tmp_path)] == ["hermes"]
    assert [t.name for t in active_targets(tmp_path)] == ["hermes"]
    result = CliRunner().invoke(targets, ["--json"])
    assert result.exit_code == 0, result.output
    row = next(row for row in json.loads(result.output) if row["target"] == "hermes")
    assert row["status"] == "active"
    assert row["source"] == ".hermes/"
    assert row["deploy_dir"] == "~/.hermes/ (--global)"


@pytest.mark.parametrize("custom_home", [False, True])
def test_hermes_native_skill_deployment(tmp_path, monkeypatch, custom_home):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("HERMES_HOME", raising=False)
    native_root = tmp_path / ".hermes"
    if custom_home:
        native_root = tmp_path / "custom-hermes"
        monkeypatch.setenv("HERMES_HOME", str(native_root))
    source = tmp_path / "apm_modules" / "example-skill"
    source.mkdir(parents=True)
    content = "---\nname: example-skill\ndescription: Example skill\n---\nDo the task.\n"
    (source / "SKILL.md").write_text(content)
    (source / "references").mkdir()
    (source / "references" / "guide.md").write_text("Reference material.\n")
    profiles = resolve_targets(tmp_path, user_scope=True, explicit_target="hermes")
    package = PackageInfo(
        package=APMPackage(name="example-skill", version="1.0.0"),
        install_path=source,
        resolved_reference=None,
        installed_at="2026-09-06T00:00:00",
        package_type=PackageType.CLAUDE_SKILL,
    )
    deployed = copy_skill_to_target(package, source, tmp_path, targets=profiles)
    destination = native_root / "skills" / "example-skill"
    assert deployed == [destination]
    assert (destination / "SKILL.md").read_text() == content
    assert (destination / "references" / "guide.md").read_text() == "Reference material.\n"
    assert not (tmp_path / ".agents").exists()
    assert set(KNOWN_TARGETS["hermes"].primitives) == {"skills"}


@pytest.mark.parametrize("target", ["hermes", ["codex", "hermes"], ["claude", "hermes"]])
def test_hermes_compiles_scoped_instructions_into_root(tmp_path, target):
    from apm_cli.commands.compile.cli import _resolve_compile_target

    (tmp_path / "apm.yml").write_text("name: hermes-test\nversion: 1.0.0\n")
    instructions = tmp_path / ".apm" / "instructions"
    instructions.mkdir(parents=True)
    (instructions / "shell.instructions.md").write_text(
        "---\napplyTo: '**/*.sh'\n---\nShell scripts must set -euo pipefail.\n"
    )
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "build.sh").write_text("#!/bin/sh\necho hello\n")
    config = CompilationConfig.from_apm_yml(
        target=_resolve_compile_target(target), with_constitution=False
    )
    assert config.strategy == "single-file"
    result = AgentsCompiler(str(tmp_path)).compile(config)
    assert result.success, result.errors
    assert "Shell scripts must set -euo pipefail." in (tmp_path / "AGENTS.md").read_text()
    assert not (tmp_path / "scripts" / "AGENTS.md").exists()
    assert not (tmp_path / "SOUL.md").exists()


def test_hermes_mixed_directory_compilation_preserves_single_file(tmp_path):
    from apm_cli.commands.compile.cli import _resolve_effective_target

    (tmp_path / ".hermes").mkdir()
    (tmp_path / ".codex").mkdir()
    target, _, _ = _resolve_effective_target(None, source_root=tmp_path)
    assert "hermes" in target
    assert CompilationConfig(target=target).strategy == "single-file"
