# Wave 26 W26-T01 Handoff

## 1. Summary

Created the AML-3 reference fix artifact for Related-Party Graph Escalation. The patch removes the tagged vulnerable graph assessment-summary policy fallback that selected owner narrative material and keeps graph side views on public risk-rationale evidence.

## 2. Implementation Details

- Added `fixes/sentinel_aml/aml_related_graph.patch`.
- Patch targets only AML-3 vulnerable-profile/proof files:
  - `internal/httpapi/graph_profile_aml3_vulnerable.go`
  - `internal/graph/repository_aml3_vulnerable.go`
  - `internal/httpapi/aml3_vulnerable_graph_test.go`
- The HTTP profile remains enabled under `aml3_vulnerable`, but graph EDD summaries keep `assessment_summary` scoped to public risk-rationale evidence.
- The vulnerable repository policy selection changes from `ExtendedAssessmentSummaryPolicy` to `GraphAssessmentSummaryPolicy`.
- The tagged proof test now verifies fixed behavior: graph EDD summaries remain available, public summary fields remain present, attacker graph access cannot see victim owner narratives, and owner EDD APIs still return owner comments to the owner.

## 3. Files Changed

- `fixes/sentinel_aml/aml_related_graph.patch`
- `fixes/sentinel_aml/README.md`
- `docs/wave_reports/wave_26_W26-T01_handoff.md`

## 4. Tests Added

- Added a fixed-profile proof test inside the patch artifact by replacing the AML-3 vulnerable leak assertion with `TestAML3FixedGraphEDDSummariesKeepAssessmentSummaryScoped`.
- No repository test files were edited directly; the proof test exists only in the reference fix patch artifact.

## 5. Tests Run

- `git apply --check --whitespace=error fixes/sentinel_aml/aml_related_graph.patch` - exit 0.
- Temporary patched copy: `C:\Users\2005g\AppData\Local\Temp\sentinel-aml-w26-32da8064ae314dcb8a5f45dcd524b759`.
- In the temporary patched copy, `git apply --check --whitespace=error fixes/sentinel_aml/aml_related_graph.patch` then `git apply fixes/sentinel_aml/aml_related_graph.patch` - exit 0.
- In the temporary patched copy with `GOTOOLCHAIN=local`, `GOFLAGS=-mod=vendor`, `GOTELEMETRY=off`, and unique temp `GOCACHE`/`APPDATA`, `go test ./...` - exit 0.
- In the temporary patched copy with the same release/offline cache isolation, `go test -tags aml3_vulnerable ./internal/httpapi -run TestAML3FixedGraphEDDSummariesKeepAssessmentSummaryScoped -count=1 -v` - exit 0.
- In the temporary patched copy with the same release/offline cache isolation, `go vet ./...` - exit 0.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"` - exit 0, 97 tests passed.
- `python -B -m unittest discover -s tests -p "test_wave21_gate.py" -k "test_exploit_extracts_flag_from_vulnerable_graph_edd_summary"` - exit 0.
- `python -B -m unittest discover -s tests -p "test_wave21_gate.py" -k "test_exploit_fails_safely_against_secure_metadata_only_graph_response"` - exit 0.
- `python -B scripts/check_docs_tree.py` - exit 0.
- `python -B scripts/check_archive_hygiene.py` - exit 0.
- Non-acceptance diagnostic: full `python -B -m unittest discover -s tests -p "test_wave21_gate.py"` exits 1 because its historical Wave 21 gate still expects exactly three exploit scripts; the focused AML-3 exploit vulnerable/safe-failure evidence above passes.

## 6. Documentation Updated

- Updated `fixes/sentinel_aml/README.md` with AML-3 purpose, scope, expected blocked exploit, and anti-coarse-fix warning.
- Created this W26-T01 handoff.

## 7. CTF Invariants Checked

- Place 2 checker GET remains owner EDD only.
- Public attack data remains credential-free.
- Graph CHECK/HAVOC coverage remains meaningful because graph entity, related-case, and EDD-summary side views remain available.
- AML-3 is blocked by visibility separation rather than endpoint removal.

## 8. Security Invariants Checked

- Fixed graph side views keep `assessment_summary` but select public risk-rationale evidence.
- Graph EDD summaries stay limited to product summary fields.
- Owner EDD access remains owner-only through `/api/customers/{customer_id}/edd`.
- No audit, export, network-room, credential, session, checker-private, debug/admin, shell, or direct-DB path is introduced.

## 9. Self-Review

- The artifact is AML-3-only and does not alter production source directly.
- AML-1 and AML-2 patch artifacts are left unchanged.
- AML-4 and AML-5 fixes remain absent.
- The patch preserves business graph functionality while removing only the assessment-summary policy leak.

## 10. Risks / Open Questions

- This task does not add a Wave 26 aggregate gate; that belongs to the next validation-gate wave.
- The historical full Wave 21 gate test is not a current-state validator after Waves 22-23 added AML-4 and AML-5 exploit scripts.

## 11. Ready for Orchestrator Review

Yes.
