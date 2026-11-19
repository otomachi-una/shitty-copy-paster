import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_side_view_lexicon.py"

spec = importlib.util.spec_from_file_location("check_side_view_lexicon", SCRIPT_PATH)
side_view_lexicon = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = side_view_lexicon
spec.loader.exec_module(side_view_lexicon)


class SideViewLexiconTest(unittest.TestCase):
    def test_side_view_private_data_policy_is_blocking(self):
        findings = side_view_lexicon.scan_text(
            "repository",
            "internal/httpapi/network_room_context.go",
            'type Dossier struct { PrivateDataPolicy string `json:"private_data_policy"` }\n',
        )

        self.assertTrue(findings)
        self.assertTrue(any(not finding.allowlisted and finding.token.lower() == "private" for finding in findings))

    def test_side_view_confidential_comment_is_blocking(self):
        findings = side_view_lexicon.scan_text(
            "repository",
            "frontend/src/shared/api/contracts.ts",
            "export interface SideView { confidential_comment?: string }\n",
        )

        self.assertTrue(findings)
        self.assertTrue(any(not finding.allowlisted and finding.token.lower() == "confidential" for finding in findings))

    def test_owner_case_note_copy_is_allowlisted(self):
        findings = side_view_lexicon.scan_text(
            "repository",
            "frontend/src/pages/CasePage.tsx",
            '<InlineNotice tone="private">Owner private note workspace.</InlineNotice>\n',
        )

        self.assertTrue(findings)
        self.assertTrue(all(finding.allowlisted for finding in findings))

    def test_owner_edd_contract_and_adapter_are_allowlisted_only_in_owner_blocks(self):
        contract_findings = side_view_lexicon.scan_text(
            "repository",
            "frontend/src/shared/api/contracts.ts",
            "export interface EDDOwnerView {\n  confidential_comment: string;\n}\n",
        )
        adapter_findings = side_view_lexicon.scan_text(
            "repository",
            "frontend/src/shared/api/adapters/customer.ts",
            'export function adaptEDDOwnerView(value: unknown): EDDOwnerView {\n  return { confidential_comment: stringField(source, "confidential_comment") };\n}\n',
        )

        self.assertTrue(contract_findings)
        self.assertTrue(adapter_findings)
        self.assertTrue(all(finding.allowlisted for finding in contract_findings))
        self.assertTrue(all(finding.allowlisted for finding in adapter_findings))


if __name__ == "__main__":
    unittest.main()
