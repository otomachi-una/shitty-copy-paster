from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


frontend_dist = load_script("build_frontend_static_dist")


class BuiltFrontendSmokeTest(unittest.TestCase):
    def test_existing_dist_can_be_sanitized_for_player_transfer(self):
        result = frontend_dist.build_frontend_static_dist(frontend_dist.DEFAULT_OUTPUT, run_npm=False)

        self.assertEqual(result["status"], "pass", result)
        self.assertIn("index.html", result["files"])
        self.assertIn("runtime-config.js", result["files"])
        self.assertFalse(any(path.endswith(".map") for path in result["files"]))


if __name__ == "__main__":
    unittest.main()
