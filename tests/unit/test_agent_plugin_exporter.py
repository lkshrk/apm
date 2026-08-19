"""Unit tests for the Agent Plugin bundle exporter."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from apm_cli.agent_plugins import load_agent_plugin
from apm_cli.bundle.agent_plugin_exporter import export_agent_plugin_bundle
from apm_cli.bundle.packer import pack_bundle

_SCHEMA_DIR = Path(__file__).parent.parent / "fixtures" / "schemas"
_PLUGIN_SCHEMA_PATH = _SCHEMA_DIR / "agent-plugins-v1.0.0-plugin.schema.json"
_MCP_SCHEMA_PATH = _SCHEMA_DIR / "agent-plugins-v1.0.0-mcp.schema.json"


def _write_lockfile(
    root: Path,
    *,
    mcp_configs: dict | None = None,
    lsp_configs: dict | None = None,
) -> None:
    (root / "apm.lock.yaml").write_text(
        yaml.safe_dump(
            {
                "lockfile_version": "1",
                "generated_at": "2025-01-01T00:00:00+00:00",
                "dependencies": [],
                "mcp_servers": sorted((mcp_configs or {}).keys()),
                "mcp_configs": mcp_configs or {},
                "lsp_servers": sorted((lsp_configs or {}).keys()),
                "lsp_configs": lsp_configs or {},
            }
        ),
        encoding="utf-8",
    )


def _validate(schema_path: Path, document: dict) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    errors = list(validator.iter_errors(document))
    assert errors == [], "\n".join(
        f"{list(error.absolute_path)}: {error.message}" for error in errors
    )


def _write_agent_project(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "apm.yml").write_text(
        """\
name: agent-pack
version: 1.2.3
description: Agent plugin pack test
author:
  name: Tester
  email: tester@example.com
license: MIT
homepage: https://example.com
repository: https://example.com/repo
keywords: [alpha, beta]
""",
        encoding="utf-8",
    )
    _write_lockfile(
        root,
        mcp_configs={
            "safe": {
                "name": "safe",
                "transport": "stdio",
                "registry": False,
                "command": "tool",
                "args": ["--ok"],
            }
        },
        lsp_configs={
            "pyright": {
                "command": "pyright-langserver",
                "extensionToLanguage": {".py": "python"},
            }
        },
    )
    (root / ".apm" / "agents").mkdir(parents=True, exist_ok=True)
    (root / ".apm" / "agents" / "agent.md").write_text("agent", encoding="utf-8")
    (root / ".apm" / "skills" / "demo").mkdir(parents=True, exist_ok=True)
    (root / ".apm" / "skills" / "demo" / "SKILL.md").write_text(
        "---\nname: demo\ndescription: Demo skill\n---\n\nUse the demo skill.\n",
        encoding="utf-8",
    )
    (root / ".apm" / "commands").mkdir(parents=True, exist_ok=True)
    (root / ".apm" / "commands" / "hello.md").write_text("command", encoding="utf-8")
    (root / ".apm" / "instructions").mkdir(parents=True, exist_ok=True)
    (root / ".apm" / "instructions" / "note.md").write_text("note", encoding="utf-8")
    (root / ".apm" / "extensions").mkdir(parents=True, exist_ok=True)
    (root / ".apm" / "extensions" / "ext.json").write_text("{}", encoding="utf-8")
    (root / ".apm" / "hooks").mkdir(parents=True, exist_ok=True)
    (root / ".apm" / "hooks" / "hooks.json").write_text(
        json.dumps({"preCommit": [{"command": "lint"}]}),
        encoding="utf-8",
    )
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "safe": {"type": "stdio", "command": "tool", "args": ["--ok"]},
                }
            }
        ),
        encoding="utf-8",
    )
    (root / ".lsp.json").write_text(
        json.dumps(
            {
                "lspServers": {
                    "raw-file-must-not-win": {
                        "command": "untrusted",
                        "extensionToLanguage": {".raw": "raw"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    for name in ("README.md", "LICENSE", "CHANGELOG.md"):
        (root / name).write_text(name, encoding="utf-8")
    return root


def test_agent_bundle_writes_namespaced_layout_and_valid_docs(tmp_path: Path) -> None:
    project = _write_agent_project(tmp_path / "project")

    result = export_agent_plugin_bundle(project, tmp_path / "build")

    bundle = result.bundle_path
    assert (bundle / "plugin.json").is_file()
    assert (bundle / "skills" / "demo" / "SKILL.md").is_file()
    assert (bundle / "com.microsoft.apm" / "agents" / "agent.md").is_file()
    assert (bundle / "com.microsoft.apm" / "commands" / "hello.md").is_file()
    assert (bundle / "com.microsoft.apm" / "instructions" / "note.md").is_file()
    assert (bundle / "com.microsoft.apm" / "extensions" / "ext.json").is_file()
    assert (bundle / "com.microsoft.apm" / "hooks" / "hooks.json").is_file()
    assert (bundle / "mcp.json").is_file()
    assert (bundle / "com.microsoft.apm" / "lsp.json").is_file()
    lsp_document = json.loads(
        (bundle / "com.microsoft.apm" / "lsp.json").read_text(encoding="utf-8")
    )
    assert set(lsp_document["lspServers"]) == {"pyright"}
    assert (bundle / "README.md").is_file()
    assert (bundle / "LICENSE").is_file()
    assert (bundle / "CHANGELOG.md").is_file()
    assert (bundle / "apm.lock.yaml").is_file()
    assert not (bundle / "apm.yml").exists()
    assert not (bundle / "apm.yaml").exists()

    plugin_json = json.loads((bundle / "plugin.json").read_text(encoding="utf-8"))
    mcp_json = json.loads((bundle / "mcp.json").read_text(encoding="utf-8"))
    lsp_json = json.loads((bundle / "com.microsoft.apm" / "lsp.json").read_text(encoding="utf-8"))
    lockfile = yaml.safe_load((bundle / "apm.lock.yaml").read_text(encoding="utf-8"))
    _validate(_PLUGIN_SCHEMA_PATH, plugin_json)
    _validate(_MCP_SCHEMA_PATH, mcp_json)
    assert plugin_json["extensions"] == {"com.microsoft.apm": {"schemaVersion": "1"}}
    assert lockfile["pack"]["format"] == "agent-plugin"
    assert lsp_json["lspServers"]["pyright"]["command"] == "pyright-langserver"
    loaded = load_agent_plugin(bundle)
    assert loaded.identity.name == "agent-pack"
    assert loaded.identity.version == "1.2.3"
    assert [skill.directory_name for skill in loaded.components.skills] == ["demo"]
    assert tuple(asset.path for asset in loaded.components.skills[0].assets) == (
        "skills/demo/SKILL.md",
    )
    assert [server.name for server in loaded.components.mcp_servers] == ["safe"]
    assert loaded.components.mcp_servers[0].executables[0].declaration == "tool"
    assert loaded.components.mcp_servers[0].executables[0].asset is None
    assert loaded.apm_extension is not None
    assert loaded.apm_extension.schema_version == "1"
    assert loaded.apm_extension.provenance.path == bundle / "plugin.json"
    assert loaded.apm_extension.provenance.json_pointer == "/extensions/com.microsoft.apm"
    assert loaded.apm_components is not None
    assert tuple(asset.path for asset in loaded.apm_components.agents.assets) == (
        "com.microsoft.apm/agents/agent.md",
    )
    assert tuple(asset.path for asset in loaded.apm_components.commands.assets) == (
        "com.microsoft.apm/commands/hello.md",
    )
    assert tuple(asset.path for asset in loaded.apm_components.instructions.assets) == (
        "com.microsoft.apm/instructions/note.md",
    )
    assert tuple(asset.path for asset in loaded.apm_components.extensions.assets) == (
        "com.microsoft.apm/extensions/ext.json",
    )
    assert loaded.apm_components.lsp is not None
    assert tuple(server.name for server in loaded.apm_components.lsp.servers) == ("pyright",)
    assert loaded.apm_components.lsp.servers[0].extension_to_language == ((".py", "python"),)
    assert loaded.apm_components.lsp.servers[0].executables[0].declaration == ("pyright-langserver")
    assert loaded.apm_components.lsp.servers[0].executables[0].asset is None
    assert tuple(asset.path for asset in loaded.apm_components.lsp.assets) == (
        "com.microsoft.apm/lsp.json",
    )
    assert loaded.apm_components.hooks is not None
    assert loaded.apm_components.hooks.document.thaw() == {"preCommit": [{"command": "lint"}]}
    assert loaded.apm_components.hooks.executables[0].declaration == "lint"
    assert loaded.apm_components.hooks.executables[0].asset is None
    assert tuple(asset.path for asset in loaded.apm_components.hooks.assets) == (
        "com.microsoft.apm/hooks/hooks.json",
    )


def test_agent_bundle_round_trip_accepts_symlinked_output_ancestor(tmp_path: Path) -> None:
    project = _write_agent_project(tmp_path / "project")
    real_output_parent = tmp_path / "real-output"
    real_output_parent.mkdir()
    output_alias = tmp_path / "output-alias"
    output_alias.symlink_to(real_output_parent, target_is_directory=True)

    result = export_agent_plugin_bundle(project, output_alias / "build")

    assert result.bundle_path == output_alias / "build" / "agent-pack-1.2.3"
    loaded = load_agent_plugin(result.bundle_path)
    assert loaded.root == result.bundle_path.resolve()
    assert loaded.apm_components is not None
    assert loaded.apm_components.agents is not None


def test_agent_bundle_dry_run_does_not_claim_default_flip_before_t10(
    tmp_path: Path, monkeypatch
) -> None:
    project = _write_agent_project(tmp_path / "project")
    monkeypatch.setattr("apm_cli.version.get_version", lambda: "0.30.0")

    result = export_agent_plugin_bundle(project, tmp_path / "build", dry_run=True)

    assert not any("defaults to Agent Plugin output" in warning for warning in result.warnings)


def test_public_packer_defaults_to_legacy_claude_plugin(tmp_path: Path) -> None:
    project = _write_agent_project(tmp_path / "project")

    result = pack_bundle(project, tmp_path / "build")

    assert (result.bundle_path / "plugin.json").is_file()
    plugin_json = json.loads((result.bundle_path / "plugin.json").read_text(encoding="utf-8"))
    assert "$schema" not in plugin_json
    assert (result.bundle_path / "agents" / "agent.md").is_file()


def test_public_packer_explicit_agent_plugin_round_trips(tmp_path: Path) -> None:
    project = _write_agent_project(tmp_path / "project")

    result = pack_bundle(project, tmp_path / "build", fmt="agent-plugin")

    loaded = load_agent_plugin(result.bundle_path)
    assert loaded.identity.name == "agent-pack"
    assert {server.name for server in loaded.components.mcp_servers} == {"safe"}


def test_agent_bundle_rejects_unrepresentable_resolved_mcp(tmp_path: Path) -> None:
    project = _write_agent_project(tmp_path / "project")
    _write_lockfile(
        project,
        mcp_configs={
            "unsafe": {
                "name": "unsafe",
                "transport": "stdio",
                "registry": False,
                "command": "sh -c tool",
            }
        },
    )

    with pytest.raises(ValueError, match=r"mcpServers\.unsafe\.command"):
        export_agent_plugin_bundle(project, tmp_path / "build")


def test_agent_bundle_rejects_nonconforming_manifest_name(tmp_path: Path) -> None:
    project = _write_agent_project(tmp_path / "project")
    apm_yml = project / "apm.yml"
    apm_yml.write_text(
        apm_yml.read_text(encoding="utf-8").replace(
            "name: agent-pack",
            "name: Invalid Plugin Name",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Agent Plugins naming rules"):
        export_agent_plugin_bundle(project, tmp_path / "build")


def test_agent_bundle_projects_production_mcp_and_excludes_dev_and_stale(
    tmp_path: Path,
) -> None:
    project = _write_agent_project(tmp_path / "project")
    apm_yml = project / "apm.yml"
    apm_yml.write_text(
        apm_yml.read_text(encoding="utf-8")
        + """
dependencies:
  mcp:
    - name: prod
      registry: false
      transport: http
      url: https://example.com/mcp
devDependencies:
  mcp:
    - name: dev-only
      registry: false
      transport: stdio
      command: dev-tool
""",
        encoding="utf-8",
    )
    configs = {
        "prod": {
            "name": "prod",
            "registry": False,
            "transport": "http",
            "url": "https://example.com/mcp",
        },
        "dev-only": {
            "name": "dev-only",
            "registry": False,
            "transport": "stdio",
            "command": "dev-tool",
        },
        "stale": {
            "name": "stale",
            "registry": False,
            "transport": "stdio",
            "command": "stale-tool",
        },
    }
    _write_lockfile(project, mcp_configs=configs)
    lockfile = yaml.safe_load((project / "apm.lock.yaml").read_text(encoding="utf-8"))
    lockfile["mcp_servers"].remove("stale")
    (project / "apm.lock.yaml").write_text(yaml.safe_dump(lockfile), encoding="utf-8")

    result = export_agent_plugin_bundle(project, tmp_path / "build")

    mcp = json.loads((result.bundle_path / "mcp.json").read_text(encoding="utf-8"))
    assert mcp["mcpServers"] == {
        "prod": {
            "type": "streamable-http",
            "url": "https://example.com/mcp",
        }
    }


def test_agent_bundle_rejects_common_literal_secret_fields(tmp_path: Path) -> None:
    project = _write_agent_project(tmp_path / "project")
    _write_lockfile(
        project,
        mcp_configs={
            "unsafe": {
                "name": "unsafe",
                "registry": False,
                "transport": "stdio",
                "command": "tool",
                "env": {"AWS_ACCESS_KEY_ID": "literal-value"},
            }
        },
    )

    with pytest.raises(ValueError, match=r"must use .* references"):
        export_agent_plugin_bundle(project, tmp_path / "build")


def test_agent_bundle_rejects_literal_secret_arguments(tmp_path: Path) -> None:
    project = _write_agent_project(tmp_path / "project")
    _write_lockfile(
        project,
        mcp_configs={
            "unsafe": {
                "name": "unsafe",
                "registry": False,
                "transport": "stdio",
                "command": "tool",
                "args": ["--token=literal-value"],
            }
        },
    )

    with pytest.raises(ValueError, match=r"argument values must use .* references"):
        export_agent_plugin_bundle(project, tmp_path / "build")


def test_agent_bundle_invalid_skill_fails_before_output_commit(tmp_path: Path) -> None:
    project = _write_agent_project(tmp_path / "project")
    (project / ".apm" / "skills" / "demo" / "SKILL.md").write_text(
        "not a valid skill manifest",
        encoding="utf-8",
    )
    build = tmp_path / "build"

    with pytest.raises(ValueError, match="failed canonical reload"):
        export_agent_plugin_bundle(project, build)

    assert not (build / "agent-pack-1.2.3").exists()


def test_agent_bundle_malformed_lsp_fails_before_directory_commit(tmp_path: Path) -> None:
    project = _write_agent_project(tmp_path / "project")
    _write_lockfile(project, lsp_configs={"broken": "not-an-object"})
    build = tmp_path / "build"
    existing = build / "agent-pack-1.2.3"
    existing.mkdir(parents=True)
    (existing / "sentinel").write_bytes(b"preserved-directory")

    with pytest.raises(ValueError, match="Every LSP server"):
        export_agent_plugin_bundle(project, build)

    assert (existing / "sentinel").read_bytes() == b"preserved-directory"


def test_agent_bundle_literal_secret_lsp_fails_before_archive_commit(tmp_path: Path) -> None:
    project = _write_agent_project(tmp_path / "project")
    _write_lockfile(
        project,
        lsp_configs={
            "unsafe": {
                "name": "unsafe",
                "command": "pyright-langserver",
                "extensionToLanguage": {".py": "python"},
                "env": {"API_TOKEN": "literal-secret"},
            }
        },
    )
    build = tmp_path / "build"
    build.mkdir()
    existing_archive = build / "agent-pack-1.2.3.zip"
    existing_archive.write_bytes(b"preserved-archive")

    with pytest.raises(ValueError, match="literal secret"):
        export_agent_plugin_bundle(project, build, archive=True)

    assert existing_archive.read_bytes() == b"preserved-archive"


def test_agent_bundle_loader_failure_preserves_existing_output(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = _write_agent_project(tmp_path / "project")
    build = tmp_path / "build"
    existing = build / "agent-pack-1.2.3"
    existing.mkdir(parents=True)
    (existing / "sentinel").write_text("preserved", encoding="utf-8")

    def _reject(_root: Path):
        raise ValueError("canonical loader rejected staged output")

    monkeypatch.setattr("apm_cli.bundle.agent_plugin_exporter.load_agent_plugin", _reject)

    with pytest.raises(ValueError, match="canonical loader rejected"):
        export_agent_plugin_bundle(project, build)

    assert (existing / "sentinel").read_text(encoding="utf-8") == "preserved"


@pytest.mark.parametrize("archive_format", ["zip", "tar.gz"])
def test_agent_bundle_archives_are_reproducible(
    tmp_path: Path,
    archive_format: str,
) -> None:
    project = _write_agent_project(tmp_path / "project")
    first = export_agent_plugin_bundle(
        project,
        tmp_path / "first",
        archive=True,
        archive_format=archive_format,
    )
    for path in project.rglob("*"):
        if path.is_file():
            os.utime(path, (2_000_000_000, 2_000_000_000))
    second = export_agent_plugin_bundle(
        project,
        tmp_path / "second",
        archive=True,
        archive_format=archive_format,
    )

    assert first.bundle_path.read_bytes() == second.bundle_path.read_bytes()
