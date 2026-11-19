import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_semantic_red_herrings.py"

spec = importlib.util.spec_from_file_location("check_semantic_red_herrings", SCRIPT_PATH)
red_herrings = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = red_herrings
spec.loader.exec_module(red_herrings)


class SemanticRedHerringsTest(unittest.TestCase):
    def test_catalog_has_enough_live_product_neutral_entries(self):
        result = red_herrings.check_semantic_red_herrings(ROOT)

        self.assertEqual(result["status"], "pass")
        self.assertGreaterEqual(result["entry_count"], 80)
        self.assertGreaterEqual(result["usage_package_count"], 2)
        self.assertIn("internal/audit", result["usage_packages"])
        self.assertIn("internal/exporting", result["usage_packages"])

    def test_parser_rejects_ctf_shaped_profile_entry(self):
        text = 'var profiles = []FieldProfile{\n\tprofile("flag_value", DataClassCase, AudienceReview, DispositionSummary, DispositionSummary, DispositionScoped, "Flag value"),\n}\n'
        profiles = red_herrings.parse_profiles(text)

        self.assertEqual(len(profiles), 1)
        self.assertIsNotNone(red_herrings.FORBIDDEN_RE.search(profiles[0].name))
        self.assertIsNotNone(red_herrings.FORBIDDEN_RE.search(profiles[0].label))


if __name__ == "__main__":
    unittest.main()
