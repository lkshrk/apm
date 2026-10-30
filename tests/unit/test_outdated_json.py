"""Unit tests for ``apm outdated --json``."""

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from apm_cli.cli import cli
from apm_cli.deps.lockfile import LockedDependency, LockFile
from apm_cli.models.dependency.types import GitReferenceType, RemoteRef

_PATCH_LOCKFILE = "apm_cli.deps.lockfile.LockFile"
_PATCH_GET_LOCKFILE_PATH = "apm_cli.deps.lockfile.get_lockfile_path"
_PATCH_MIGRATE = "apm_cli.deps.lockfile.migrate_lockfile_if_needed"
_PATCH_DOWNLOADER = "apm_cli.deps.github_downloader.GitHubPackageDownloader"
_PATCH_AUTH = "apm_cli.core.auth.AuthResolver"
_PATCH_GET_APM_DIR = "apm_cli.core.scope.get_apm_dir"


def _lockfile(deps):
    lf = LockFile()
    lf.dependencies = deps
    return lf


def _tag(name, sha="abc123"):
    return RemoteRef(name=name, ref_type=GitReferenceType.TAG, commit_sha=sha)


def _branch(name, sha):
    return RemoteRef(name=name, ref_type=GitReferenceType.BRANCH, commit_sha=sha)


@patch(_PATCH_AUTH)
@patch(_PATCH_DOWNLOADER)
@patch(_PATCH_MIGRATE)
@patch(_PATCH_GET_LOCKFILE_PATH)
@patch(_PATCH_GET_APM_DIR)
@patch(_PATCH_LOCKFILE)
def test_json_lists_every_row_and_nothing_else(
    mock_lf_cls, mock_get_apm_dir, mock_get_path, _migrate, mock_dl_cls, _auth, tmp_path
):
    mock_get_apm_dir.return_value = tmp_path
    mock_get_path.return_value = tmp_path / "apm.lock.yaml"
    mock_lf_cls.read.return_value = _lockfile(
        {
            "org/tagged": LockedDependency(
                repo_url="org/tagged", resolved_ref="v1.0.0", resolved_commit="aaa"
            ),
            "org/branch": LockedDependency(
                repo_url="org/branch", resolved_ref="", resolved_commit="old"
            ),
            "org/current": LockedDependency(
                repo_url="org/current", resolved_ref="v2.0.0", resolved_commit="bbb"
            ),
            "org/local": LockedDependency(repo_url="org/local", source="local"),
        }
    )
    downloader = MagicMock()
    mock_dl_cls.return_value = downloader
    remote = {
        "org/tagged": [_tag("v1.1.0"), _tag("v1.0.0")],
        "org/branch": [_branch("main", "newtip0123456789")],
        "org/current": [_tag("v2.0.0")],
    }
    downloader.list_remote_refs.side_effect = lambda ref: remote[ref.repo_url]

    result = CliRunner().invoke(cli, ["outdated", "--json"])

    assert result.exit_code == 0, result.output
    assert result.stderr == ""
    rows = json.loads(result.stdout)["dependencies"]
    assert [(r["package"], r["current"], r["latest"], r["status"], r["source"]) for r in rows] == [
        ("org/tagged", "v1.0.0", "v1.1.0", "outdated", "git tags"),
        ("org/branch", "(default)", "newtip01", "outdated", "git branch"),
        ("org/current", "v2.0.0", "v2.0.0", "up-to-date", "git tags"),
    ]
    assert {"wanted", "outside_constraint", "extra_tags"} <= rows[0].keys()


@patch(_PATCH_AUTH)
@patch(_PATCH_DOWNLOADER)
@patch(_PATCH_MIGRATE)
@patch(_PATCH_GET_LOCKFILE_PATH)
@patch(_PATCH_GET_APM_DIR)
@patch(_PATCH_LOCKFILE)
def test_json_reports_a_failed_check_as_unknown(
    mock_lf_cls, mock_get_apm_dir, mock_get_path, _migrate, mock_dl_cls, _auth, tmp_path
):
    mock_get_apm_dir.return_value = tmp_path
    mock_get_path.return_value = tmp_path / "apm.lock.yaml"
    mock_lf_cls.read.return_value = _lockfile(
        {
            "org/broken": LockedDependency(
                repo_url="org/broken", resolved_ref="v1.0.0", resolved_commit="aaa"
            )
        }
    )
    downloader = MagicMock()
    mock_dl_cls.return_value = downloader
    downloader.list_remote_refs.side_effect = RuntimeError("network down")

    result = CliRunner().invoke(cli, ["outdated", "--json", "-j", "0"])

    assert result.exit_code == 0, result.output
    rows = json.loads(result.stdout)["dependencies"]
    assert [(r["package"], r["status"]) for r in rows] == [("org/broken", "unknown")]


@patch(_PATCH_MIGRATE)
@patch(_PATCH_GET_LOCKFILE_PATH)
@patch(_PATCH_GET_APM_DIR)
@patch(_PATCH_LOCKFILE)
def test_json_empty_lockfile_is_an_empty_list(
    mock_lf_cls, mock_get_apm_dir, mock_get_path, _migrate, tmp_path
):
    mock_get_apm_dir.return_value = tmp_path
    mock_get_path.return_value = tmp_path / "apm.lock.yaml"
    mock_lf_cls.read.return_value = _lockfile({})

    result = CliRunner().invoke(cli, ["outdated", "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {"dependencies": []}


@patch(_PATCH_MIGRATE)
@patch(_PATCH_GET_LOCKFILE_PATH)
@patch(_PATCH_GET_APM_DIR)
@patch(_PATCH_LOCKFILE)
def test_json_missing_lockfile_errors_on_stderr(
    mock_lf_cls, mock_get_apm_dir, mock_get_path, _migrate, tmp_path
):
    mock_get_apm_dir.return_value = tmp_path
    mock_get_path.return_value = tmp_path / "apm.lock.yaml"
    mock_lf_cls.read.return_value = None

    result = CliRunner().invoke(cli, ["outdated", "--json"])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert json.loads(result.stderr) == {"error": "no_lockfile"}
