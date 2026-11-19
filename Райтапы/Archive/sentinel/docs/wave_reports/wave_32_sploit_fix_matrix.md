# Wave 32 Sploit/Fix Matrix

W32-T03 makes the five planned exploit/fix rows explicit inside the archive-
free stability path. `ad-stability-gate` runs the competition matrix gate, all
five sploit syntax checks, all five fix patch checks, checker tests, and
CHECK/HAVOC coverage without creating release archives, player bundles,
manifests, or checksums.

| ID | vulnerable profile builds | sploit syntax | sploit expected path | fix patch applies | fixed profile blocks sploit | checker stays green | CHECK/HAVOC stays green |
| --- | --- | --- | --- | --- | --- | --- | --- |
| AML-1 | `scripts/check_wave14_gate.py` requires `go test -tags aml1_vulnerable ./...`. | `sploits/sentinel_aml/aml_dedup_preview.py` compiles and accepts host, port, and attack info. | `/api/cases/{source_case_id}/duplicates`; `/api/cases/{source_case_id}/duplicates/{victim_case_id}/merge-preview`. | `scripts/check_wave24_gate.py` verifies `fixes/sentinel_aml/aml_dedup_preview.patch` with `git apply --check`. | `test_aml1_exploit_fails_safely_on_fixed_public_output`. | Fixed evidence includes checker unittest discovery and `go test ./...`. | `check_dedup`. |
| AML-2 | `scripts/check_wave15_gate.py` requires `go test -tags aml2_vulnerable ./...`. | `sploits/sentinel_aml/aml_audit_timeline.py` compiles and accepts host, port, and attack info. | `/api/entities/{entity_hint}/activity`. | `scripts/check_wave25_gate.py` verifies `fixes/sentinel_aml/aml_audit_timeline.patch` with `git apply --check`. | `test_aml2_exploit_fails_safely_on_fixed_redacted_output_and_preserves_event`. | Fixed evidence includes checker unittest discovery and `go test ./...`. | `check_audit`. |
| AML-3 | `scripts/check_wave16_gate.py` requires `go test -tags aml3_vulnerable ./...`. | `sploits/sentinel_aml/aml_related_graph.py` compiles and accepts host, port, and attack info. | `/api/graph/entities/{quoted_hint}/edd-summaries`. | `scripts/check_wave26_gate.py` verifies `fixes/sentinel_aml/aml_related_graph.patch` with `git apply --check`. | `test_aml3_exploit_fails_safely_on_fixed_public_graph_output`. | Fixed evidence includes checker unittest discovery and `go test ./...`. | `check_graph`. |
| AML-4 | `scripts/check_wave17_gate.py` requires `go test -p 1 -tags aml4_vulnerable ./...`. | `sploits/sentinel_aml/aml_export_redaction.py` compiles and accepts host, port, and attack info. | `/api/disputes/{dispute_id}/export`; `/api/exports/{export_id}`. | `scripts/check_wave27_gate.py` verifies `fixes/sentinel_aml/aml_export_redaction.patch` with `git apply --check`. | `test_aml4_exploit_fails_safely_on_fixed_public_export_output`. | Fixed evidence includes checker unittest discovery and `go test ./...`. | `check_export`. |
| AML-5 | `scripts/check_wave18_gate.py` requires `go test -p 1 -tags aml5_vulnerable ./...`. | `sploits/sentinel_aml/aml_network_room.py` compiles and accepts host, port, and attack info. | `/api/network/rooms`; `/api/network/rooms/{room_id}/join`; `/api/network/rooms/{room_id}/dossier`. | `scripts/check_wave28_gate.py` verifies `fixes/sentinel_aml/aml_network_room.patch` with `git apply --check`. | `test_exploit_fails_safely_on_accepted_fixed_fixture`. | Fixed evidence includes checker unittest discovery and `go test ./...`. | `check_network_room`. |

The matrix is validated by
`scripts/check_competition_matrix_gate.py::check_wave32_sploit_syntax_and_business_paths`,
`check_wave32_fix_patch_and_simulation_evidence`, and
`check_wave32_docs_and_report_evidence`. These checks require all sploits to
stay on normal business APIs and reject direct DB, debug/admin, and shell
shortcuts. Existing fix-wave tests keep normal business behavior live while
blocking only the intended leakage path.
