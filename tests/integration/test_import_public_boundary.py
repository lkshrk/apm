from __future__ import annotations

import json
from importlib.resources import files

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

from apm_cli.cli import cli
from apm_cli.commands import import_cmd as command
from apm_cli.factory import ClientFactory
from apm_cli.importing import ImportService
from apm_cli.integration.targets import KNOWN_TARGETS


def _plan() -> dict:
    return {
        "schema_version": 1,
        "coordinator": "standalone",
        "operation_id": "0" * 32,
        "plan_id": "0" * 64,
        "resolution_id": "0" * 64,
        "scope": "global",
        "sources": [],
        "candidate_set_id": "0" * 64,
        "inventory_fingerprint": "0" * 64,
        "items": [],
        "summary": {},
        "warnings": [],
        "blockers": [],
    }


def test_import_source_choices_and_default_are_registry_derived(monkeypatch, tmp_path):
    registered = tuple(sorted(set(KNOWN_TARGETS) | set(ClientFactory.supported_clients())))
    source_option = next(
        parameter for parameter in command.import_cmd.params if parameter.name == "sources"
    )
    assert command.registered_import_sources() == registered
    assert command._expand_sources((), global_=False) == registered
    assert command._expand_sources(("all",), global_=False) == registered
    assert set(source_option.type.choices) == {*registered, "all"}

    captured = []

    def scan(_self, **kwargs):
        captured.append(kwargs["sources"])
        return _plan()

    monkeypatch.setattr(ImportService, "scan", scan)
    runner = CliRunner()
    candidate = tmp_path / "candidates.json"
    for extra in ([], ["--from", "all"]):
        result = runner.invoke(
            cli,
            ["import", "--global", *extra, "--candidate-file", str(candidate)],
        )
        assert result.exit_code == 0, result.output
    assert captured == [registered, registered]


def test_project_omitted_sources_discovers_contained_codex_and_vscode_only(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APM_E2E_TESTS", "1")
    workspace = tmp_path / "workspace"
    codex = workspace / ".codex/config.toml"
    vscode = workspace / ".vscode/mcp.json"
    codex.parent.mkdir(parents=True)
    vscode.parent.mkdir(parents=True)
    codex.write_text('[mcp_servers.codex-demo]\ncommand = "codex-demo"\n', encoding="utf-8")
    vscode.write_text(
        json.dumps({"servers": {"vscode-demo": {"type": "stdio", "command": "vscode-demo"}}}),
        encoding="utf-8",
    )
    candidate = tmp_path / "protocol/candidates.json"
    monkeypatch.chdir(workspace)

    result = CliRunner().invoke(
        cli,
        ["import", "--candidate-file", str(candidate)],
    )

    assert result.exit_code == 0, result.output
    envelope = json.loads(result.stdout)
    assert envelope["plan"]["scope"] == "project"
    assert envelope["plan"]["project_root"] == str(workspace)
    assert {
        (item["name"], tuple(item["current_targets"])) for item in envelope["plan"]["items"]
    } == {("codex-demo", ("codex",)), ("vscode-demo", ("vscode",))}
    assert not (home / ".apm").exists()
    assert not (home / ".codex").exists()
    assert not (home / ".vscode").exists()


@pytest.mark.parametrize(
    "source", ["cursor", "agent-skills", "intellij", "copilot-cowork", "grok-cloud"]
)
def test_public_cli_accepts_registered_import_sources(monkeypatch, tmp_path, source):
    captured = []
    monkeypatch.setattr(
        ImportService,
        "scan",
        lambda _self, **kwargs: captured.append(kwargs["sources"]) or _plan(),
    )
    result = CliRunner().invoke(
        cli,
        [
            "import",
            "--global",
            "--from",
            source,
            "--candidate-file",
            str(tmp_path / "candidates.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert captured == [(source,)]


def test_packaged_candidate_schema_accepts_registry_and_future_source_names():
    schema = json.loads(
        files("apm_cli").joinpath("schemas/import-candidates-v1.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    names = sorted(set(KNOWN_TARGETS) | set(ClientFactory.supported_clients()) | {"future-agent"})
    for name in names:
        validator.validate(
            {
                "schema_version": 1,
                "coordinator": "standalone",
                "scope": "global",
                "sources": [name],
                "candidate_set_id": "0" * 64,
                "source_preimages": [
                    {
                        "id": "source",
                        "absolute_path": "/source",
                        "kind": "file",
                        "size": 0,
                        "mode": 384,
                        "content_fingerprint": "0" * 64,
                    }
                ],
                "candidates": [
                    {
                        "id": "candidate",
                        "kind": "mcp",
                        "name": "demo",
                        "root_id": "root",
                        "source_handle": "root:demo",
                        "source_target": [name],
                        "provenance": "local-only",
                        "payload": {},
                        "content_fingerprint": "0" * 64,
                        "source_preimage_ids": ["source"],
                        "executable_paths": [],
                    }
                ],
            }
        )
