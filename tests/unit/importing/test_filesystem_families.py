from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from apm_cli.importing.compiled_instructions import adopt_compiled_instruction
from apm_cli.importing.discovery import (
    NativeResource,
    discover_filesystem_resources,
    mapping_root,
    user_scope_mappings,
)
from apm_cli.importing.service import ImportService
from apm_cli.integration.targets import KNOWN_TARGETS, PrimitiveMapping


def _home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    return home


def _native_file(
    home: Path, target: str, kind: str, mapping: PrimitiveMapping, *, body: str
) -> Path:
    profile = KNOWN_TARGETS[target].for_scope(user_scope=True)
    base = mapping_root(profile, mapping, home=home) / mapping.subdir
    name = f"{target}-{kind}"
    if mapping.extension.startswith("/"):
        path = base / name / mapping.extension[1:]
    elif mapping.extension.startswith("."):
        path = base / f"{name}{mapping.extension}"
    else:
        path = base / mapping.extension
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path.parent if mapping.extension.startswith("/") else path


def _tree_state(root: Path) -> list[tuple[str, int, int, bytes | None]]:
    return [
        (
            path.relative_to(root).as_posix(),
            path.stat().st_mode,
            path.stat().st_mtime_ns,
            path.read_bytes() if path.is_file() else None,
        )
        for path in sorted(root.rglob("*"))
    ]


def _generic_matrix() -> list[tuple[str, str, PrimitiveMapping]]:
    matrix = []
    for target, profile in sorted(KNOWN_TARGETS.items()):
        if not profile.user_supported:
            continue
        scoped = profile.for_scope(user_scope=True)
        if scoped is None:
            continue
        matrix.extend(
            (target, kind, mapping)
            for kind, mapping in sorted(user_scope_mappings(scoped).items())
            if mapping.import_strategy == "generic"
        )
    return matrix


def test_every_generic_mapping_scans_offline_without_mutating_native_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home = _home(monkeypatch, tmp_path)
    matrix = _generic_matrix()
    protocol_kinds = {
        "instructions": "instruction",
        "agents": "agent",
        "commands": "command",
        "prompts": "command",
        "skills": "skill",
    }
    expected = {}
    for target, kind, mapping in matrix:
        path = _native_file(
            home, target, kind, mapping, body=f"---\nname: {target}-{kind}\n---\n# native\n"
        ).resolve()
        expected[path] = (target, protocol_kinds[kind], f"{target}-{kind}")
    before = _tree_state(home)

    def no_network(*_args, **_kwargs):
        raise AssertionError("filesystem discovery attempted network access")

    monkeypatch.setattr(socket, "create_connection", no_network)
    resources = discover_filesystem_resources({target for target, _, _ in matrix}, home=home)

    generic = [resource for resource in resources if resource.strategy == "generic"]
    assert {resource.path for resource in generic} == set(expected)
    for resource in generic:
        target, kind, name = expected[resource.path]
        assert resource.targets == (target,)
        assert (resource.kind, resource.name) == (kind, name)
    assert _tree_state(home) == before


@pytest.mark.parametrize(
    ("target", "relative", "format_id", "body"),
    [
        ("claude", "rules/python.md", "claude_rules", "---\npaths: [src/**]\n---\n# Claude\n"),
        (
            "kiro",
            "steering/python.md",
            "kiro_steering",
            "---\ninclusion: fileMatch\nfileMatchPattern: 'src/**'\n---\n# Kiro\n",
        ),
    ],
)
def test_compiled_instruction_adoption_preserves_exact_target_native_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    target: str,
    relative: str,
    format_id: str,
    body: str,
) -> None:
    home = _home(monkeypatch, tmp_path)
    path = home / KNOWN_TARGETS[target].for_scope(user_scope=True).root_dir / relative
    path.parent.mkdir(parents=True)
    path.write_bytes(body.encode())

    resource = next(
        item
        for item in discover_filesystem_resources((target,), home=home)
        if item.path == path.resolve() and item.strategy == "compiled"
    )
    adopted = adopt_compiled_instruction(resource)

    assert adopted.target == target
    assert adopted.format_id == format_id
    assert adopted.relative_path == Path(relative)
    assert adopted.content == path.read_bytes()
    assert resource.targets == (target,)


def test_compiled_instruction_rejects_broadened_scope(tmp_path: Path) -> None:
    root = tmp_path / ".claude"
    source = root / "rules" / "demo.md"
    source.parent.mkdir(parents=True)
    source.write_text("# demo\n", encoding="utf-8")

    with pytest.raises(ValueError, match="exactly one"):
        adopt_compiled_instruction(
            NativeResource(
                root=root,
                path=source,
                kind="instruction",
                name="demo",
                targets=("claude", "kiro"),
                strategy="compiled",
            )
        )


@pytest.mark.parametrize("target", ["claude", "kiro"])
def test_compiled_instruction_apply_and_second_scan_has_no_work(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, target: str
) -> None:
    home = _home(monkeypatch, tmp_path)
    monkeypatch.setenv("APM_E2E_TESTS", "1")
    mapping = user_scope_mappings(KNOWN_TARGETS[target].for_scope(user_scope=True))["instructions"]
    _native_file(home, target, "instructions", mapping, body="# Native instruction\n")
    candidates = tmp_path / "candidates.json"
    plan_path = tmp_path / "plan.json"

    ImportService().scan(
        sources=(target,),
        candidate_file=candidates,
        plan_json=plan_path,
        coordinator="standalone",
    )
    result = ImportService().apply(
        candidate_file=candidates,
        plan_file=plan_path,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )
    assert result["state"] == "complete"

    second = ImportService().scan(
        sources=(target,),
        candidate_file=tmp_path / f"second-{target}.json",
        plan_json=None,
        coordinator="standalone",
    )
    assert not [
        value
        for value in second["items"]
        if value["classification"] in {"importable", "local-package"}
    ]


def test_existing_imported_resource_classifies_already_managed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home = _home(monkeypatch, tmp_path)
    mapping = user_scope_mappings(KNOWN_TARGETS["cursor"].for_scope(user_scope=True))["agents"]
    _native_file(home, "cursor", "agents", mapping, body="# Agent\n")
    candidates = tmp_path / "candidates.json"
    first = ImportService().scan(
        sources=("cursor",),
        candidate_file=candidates,
        plan_json=None,
        coordinator="standalone",
    )
    item = next(value for value in first["items"] if value["kind"] == "agent")
    candidate_id = item["candidate_ids"][0]
    metadata = home / ".apm" / "imported" / "agent" / "owned" / ".apm-import.json"
    metadata.parent.mkdir(parents=True)
    metadata.write_text(json.dumps({"candidate_ids": [candidate_id]}), encoding="utf-8")

    second = ImportService().scan(
        sources=("cursor",),
        candidate_file=tmp_path / "second.json",
        plan_json=None,
        coordinator="standalone",
    )
    managed = next(value for value in second["items"] if candidate_id in value["candidate_ids"])
    assert managed["classification"] == "already-managed"
    assert managed["proposed_targets"] == ["cursor"]


def test_generic_skill_scan_apply_audit_and_second_scan_is_managed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from apm_cli.importing import service as importing

    home = _home(monkeypatch, tmp_path)
    mapping = user_scope_mappings(KNOWN_TARGETS["hermes"].for_scope(user_scope=True))["skills"]
    _native_file(
        home,
        "hermes",
        "skills",
        mapping,
        body="---\nname: hermes-skills\n---\n# Native\n",
    )
    candidates = tmp_path / "candidates.json"
    plan_path = tmp_path / "plan.json"
    first = ImportService().scan(
        sources=("hermes",),
        candidate_file=candidates,
        plan_json=plan_path,
        coordinator="standalone",
    )
    item = next(value for value in first["items"] if value["kind"] == "skill")
    assert item["classification"] == "local-package"
    assert item["proposed_targets"] == ["hermes"]

    audited = []
    real_audit = importing._audit_import

    def record_audit(path: Path) -> None:
        real_audit(path)
        audited.append(path)

    monkeypatch.setattr(importing, "_audit_import", record_audit)
    result = ImportService().apply(
        candidate_file=candidates,
        plan_file=plan_path,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )
    assert result["state"] == "complete"
    assert audited == [home / ".apm" / "apm.yml"]

    second = ImportService().scan(
        sources=("hermes",),
        candidate_file=tmp_path / "second.json",
        plan_json=None,
        coordinator="standalone",
    )
    rescanned = next(value for value in second["items"] if value["kind"] == "skill")
    assert rescanned["classification"] == "already-managed"
    assert rescanned["proposed_targets"] == ["hermes"]


def test_shared_skill_apply_preserves_union_and_second_scan_has_no_work(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home = _home(monkeypatch, tmp_path)
    monkeypatch.setenv("APM_E2E_TESTS", "1")
    skill = home / ".agents" / "skills" / "shared" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: shared\n---\n# Shared\n", encoding="utf-8")
    candidates = tmp_path / "candidates.json"
    plan_path = tmp_path / "plan.json"

    first = ImportService().scan(
        sources=("agent-skills", "codex"),
        candidate_file=candidates,
        plan_json=plan_path,
        coordinator="standalone",
    )
    item = next(value for value in first["items"] if value["kind"] == "skill")
    assert item["proposed_targets"] == ["agent-skills", "codex"]

    result = ImportService().apply(
        candidate_file=candidates,
        plan_file=plan_path,
        coordinator="standalone",
        omni_preimage_set=None,
        token=None,
    )
    assert result["state"] == "complete"

    second = ImportService().scan(
        sources=("agent-skills", "codex"),
        candidate_file=tmp_path / "second.json",
        plan_json=None,
        coordinator="standalone",
    )
    assert not [
        value
        for value in second["items"]
        if value["classification"] in {"importable", "local-package"}
    ]
