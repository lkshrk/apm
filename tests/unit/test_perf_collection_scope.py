from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def test_perf_collection_hook_skips_only_perf_items(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "apm_perf_conftest", Path(__file__).parents[1] / "perf" / "conftest.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    class Item:
        def __init__(self, path: Path):
            self.path = path
            self.markers = []

        def add_marker(self, marker):
            self.markers.append(marker)

    unit = Item(tmp_path / "tests" / "unit" / "test_unit.py")
    perf = Item(module.PERF_ROOT / "test_perf.py")
    module.pytest_collection_modifyitems(None, [unit, perf])

    assert unit.markers == []
    assert [marker.mark.name for marker in perf.markers] == ["skipif"]
