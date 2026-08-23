from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from apm_cli.importing.plugin_discovery import (
    capture_activation,
    discover_plugin_state,
    restore_activation,
)
from apm_cli.importing.secure import SecureRoot


def _plugin(path: Path, manifest: dict[str, object] | str = '{"name":"demo"}') -> Path:
    (path / ".claude-plugin").mkdir(parents=True)
    value = json.dumps(manifest) if isinstance(manifest, dict) else manifest
    (path / ".claude-plugin" / "plugin.json").write_text(value, encoding="utf-8")
    return path


def _activation(root: Path, reference: str, plugin: Path, **extra: object) -> Path:
    path = root / "plugins" / "installed_plugins.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"plugins": {reference: [{"installPath": str(plugin), **extra}]}}),
        encoding="utf-8",
    )
    return path


def _tree_state(root: Path) -> dict[str, tuple[int, int, bytes | None]]:
    paths = [root, *sorted(root.rglob("*"))]
    return {
        path.relative_to(root).as_posix(): (
            stat.S_IMODE(path.lstat().st_mode),
            path.lstat().st_mtime_ns,
            path.read_bytes() if path.is_file() and not path.is_symlink() else None,
        )
        for path in paths
    }


def test_marketplace_provenance_preserves_ref_version_and_install_path(tmp_path: Path) -> None:
    root = tmp_path / ".claude"
    plugin = _plugin(root / "plugins" / "cache" / "market" / "demo" / "1.2.3")
    _activation(root, "demo@market", plugin, version="1.2.3", gitCommitSha="a" * 40)
    (root / "plugins" / "known_marketplaces.json").write_text(
        json.dumps(
            {
                "market": {
                    "source": {
                        "source": "github",
                        "repo": "owner/repo",
                        "ref": "stable",
                        "path": "catalog/marketplace.json",
                    },
                    "installLocation": str(root / "plugins" / "marketplaces" / "market"),
                }
            }
        ),
        encoding="utf-8",
    )

    first = discover_plugin_state({"claude": root})
    second = discover_plugin_state({"claude": root})

    assert first == second
    assert first.plugins[0].provenance == "marketplace"
    assert first.plugins[0].payload == {
        "plugin": "demo",
        "marketplace": "market",
        "version": "1.2.3",
        "ref": "a" * 40,
    }
    source = first.marketplaces[0].payload["source"]
    assert source["url"] == "https://github.com/owner/repo"
    assert source["ref"] == "stable"
    assert source["path"] == "catalog/marketplace.json"
    assert Path(source["install_path"]).parts[-3:] == ("plugins", "marketplaces", "market")


def test_clean_local_git_plugin_uses_immutable_revision(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path / "repo" / "plugin")
    subprocess.run(["git", "init", str(tmp_path / "repo")], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(tmp_path / "repo"), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(["git", "-C", str(tmp_path / "repo"), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(tmp_path / "repo"), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path / "repo"), "commit", "-m", "fixture"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path / "repo"),
            "remote",
            "add",
            "origin",
            "ssh://git@example.com/owner/repo.git",
        ],
        check=True,
    )
    root = tmp_path / ".claude"
    _activation(root, "demo", plugin)

    discovered = discover_plugin_state({"claude": root}).plugins[0]

    assert discovered.provenance == "git"
    assert discovered.payload["source"] == "ssh://git@example.com/owner/repo.git"
    assert len(discovered.payload["ref"]) == 40
    assert discovered.payload["path"] == "plugin"


def test_git_provenance_disables_fsmonitor_and_writes_nothing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    plugin = _plugin(repo / "plugin")
    marker = tmp_path / "fsmonitor-executed"
    hook = tmp_path / "fsmonitor.sh"
    hook.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    hook.chmod(0o700)
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "fixture"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "remote", "add", "origin", "https://example.com/repo.git"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "config", "core.fsmonitor", str(hook)], check=True)
    root = tmp_path / ".claude"
    _activation(root, "demo", plugin)
    before = _tree_state(repo)

    discovered = discover_plugin_state({"claude": root}).plugins[0]

    assert discovered.provenance == "git"
    assert not marker.exists()
    assert _tree_state(repo) == before


def test_cache_snapshot_is_physically_deduplicated_across_targets(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path / "cache" / "demo")
    roots = {name: tmp_path / f".{name}" for name in ("claude", "codex")}
    for root in roots.values():
        _activation(root, "demo", plugin)

    discovery = discover_plugin_state(roots)

    assert len(discovery.plugins) == 1
    assert discovery.plugins[0].targets == ("claude", "codex")
    assert discovery.plugins[0].payload == {"source": "secured-path"}


@pytest.mark.skipif(os.name == "nt", reason="symlink creation is not generally available")
def test_symlinked_plugin_state_parent_blocks_without_reading_outside(tmp_path: Path) -> None:
    root = tmp_path / ".claude"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    plugin = _plugin(tmp_path / "external-plugin")
    installed = outside / "installed_plugins.json"
    installed.write_text(
        json.dumps({"plugins": {"demo": [{"installPath": str(plugin)}]}}), encoding="utf-8"
    )
    marketplace = outside / "known_marketplaces.json"
    marketplace.write_text(
        json.dumps({"market": {"source": {"source": "github", "repo": "owner/repo"}}}),
        encoding="utf-8",
    )
    installed.chmod(0o640)
    marketplace.chmod(0o640)
    before = _tree_state(outside)
    (root / "plugins").symlink_to(outside, target_is_directory=True)

    discovery = discover_plugin_state({"claude": root})

    assert [item.blocked_reason for item in discovery.plugins] == ["plugin-state-path-unsafe"]
    assert discovery.plugins[0].activation_paths == ()
    assert [item.blocked_reason for item in discovery.marketplaces] == ["plugin-state-path-unsafe"]
    assert all(
        item.path.resolve() not in {installed.resolve(), marketplace.resolve()}
        for item in discovery.plugins
    )
    assert _tree_state(outside) == before


def test_reparse_plugin_state_blocks_before_registry_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / ".claude"
    plugin_dir = root / "plugins"
    plugin_dir.mkdir(parents=True)
    registry = plugin_dir / "installed_plugins.json"
    registry.write_text('{"token":"outside-secret"}', encoding="utf-8")
    before = (registry.read_bytes(), registry.stat().st_mtime_ns)
    original = SecureRoot._is_link_or_reparse
    monkeypatch.setattr(
        SecureRoot,
        "_is_link_or_reparse",
        staticmethod(lambda path: path == plugin_dir or original(path)),
    )

    discovery = discover_plugin_state({"claude": root})

    assert discovery.plugins[0].blocked_reason == "plugin-state-path-unsafe"
    assert "outside-secret" not in repr(discovery)
    assert (registry.read_bytes(), registry.stat().st_mtime_ns) == before


@pytest.mark.skipif(os.name == "nt", reason="symlink creation is not generally available")
@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("installed_plugins.json", "plugin-activation-path-unsafe"),
        ("known_marketplaces.json", "marketplace-registry-path-unsafe"),
    ],
)
def test_symlinked_registry_leaf_blocks_without_reading_outside(
    tmp_path: Path, filename: str, expected: str
) -> None:
    root = tmp_path / ".claude"
    plugin_dir = root / "plugins"
    plugin_dir.mkdir(parents=True)
    outside = tmp_path / filename
    secret = f"outside-{filename}-secret"
    outside.write_text(json.dumps({"token": secret}), encoding="utf-8")
    outside.chmod(0o640)
    before = (
        outside.read_bytes(),
        stat.S_IMODE(outside.stat().st_mode),
        outside.stat().st_mtime_ns,
    )
    (plugin_dir / filename).symlink_to(outside)

    discovery = discover_plugin_state({"claude": root})
    records = discovery.plugins if filename.startswith("installed") else discovery.marketplaces

    assert [item.blocked_reason for item in records] == [expected]
    assert secret not in repr(discovery)
    assert (
        outside.read_bytes(),
        stat.S_IMODE(outside.stat().st_mode),
        outside.stat().st_mtime_ns,
    ) == before


def test_malformed_escape_and_missing_plugins_block(tmp_path: Path) -> None:
    root = tmp_path / ".claude"
    malformed = _plugin(root / "plugins" / "malformed", "{")
    non_object = _plugin(root / "plugins" / "non-object", "[]")
    escaped = _plugin(
        root / "plugins" / "escaped", {"name": "escaped", "commands": "../../outside"}
    )
    installed = root / "plugins" / "installed_plugins.json"
    installed.parent.mkdir(parents=True, exist_ok=True)
    installed.write_text(
        json.dumps(
            {
                "plugins": {
                    "malformed": [{"installPath": str(malformed)}],
                    "escaped": [{"installPath": str(escaped)}],
                    "missing": [{"installPath": str(root / "plugins" / "missing")}],
                    "non-object": [{"installPath": str(non_object)}],
                }
            }
        ),
        encoding="utf-8",
    )

    reasons = {
        item.name: item.blocked_reason for item in discover_plugin_state({"claude": root}).plugins
    }

    assert reasons == {
        "escaped": "plugin-manifest-malformed",
        "malformed": "plugin-manifest-malformed",
        "missing": "plugin-install-path-missing",
        "non-object": "plugin-manifest-malformed",
    }


def test_marketplace_path_escape_blocks(tmp_path: Path) -> None:
    root = tmp_path / ".claude"
    path = root / "plugins" / "known_marketplaces.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {"market": {"source": {"source": "github", "repo": "owner/repo", "path": "../escape"}}}
        ),
        encoding="utf-8",
    )

    marketplace = discover_plugin_state({"claude": root}).marketplaces[0]

    assert marketplace.blocked_reason == "marketplace-provenance-malformed"


@pytest.mark.parametrize(
    "entry",
    [
        {"source": {"url": "https://user:supersecret@example.com/repo.git"}},
        {"source": {"url": "https://example.com/repo.git?token=supersecret"}},
        {"source": {"url": "https://example.com/repo.git#api-key=supersecret"}},
        {"source": {"url": "https://example.com/repo.git"}, "authorization": "supersecret"},
    ],
)
def test_marketplace_credentials_block_without_literal_leak(
    tmp_path: Path, entry: dict[str, object]
) -> None:
    root = tmp_path / ".claude"
    path = root / "plugins" / "known_marketplaces.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"market": entry}), encoding="utf-8")

    discovery = discover_plugin_state({"claude": root})

    assert discovery.marketplaces[0].blocked_reason == "marketplace-provenance-malformed"
    assert "supersecret" not in repr(discovery)


def test_activation_capture_restores_exact_bytes_and_mode(tmp_path: Path) -> None:
    path = tmp_path / "installed_plugins.json"
    original = b'{"plugins":{}}\n'
    path.write_bytes(original)
    path.chmod(0o640)
    state = capture_activation(path)
    path.write_bytes(b"{}")
    path.chmod(0o600)

    restore_activation(state)

    assert path.read_bytes() == original
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o640
