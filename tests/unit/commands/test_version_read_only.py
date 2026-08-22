from __future__ import annotations

import os
import subprocess
import sys


def test_version_does_not_materialize_config(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    result = subprocess.run(
        [sys.executable, "-m", "apm_cli.cli", "--version"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert not (home / ".apm").exists()
