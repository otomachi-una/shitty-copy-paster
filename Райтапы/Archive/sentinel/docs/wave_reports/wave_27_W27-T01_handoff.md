# W27-T01 Handoff - AML-4 Reference Fix Patch Artifact

## 1. Summary

Created the AML-4 reference fix patch artifact
`fixes/sentinel_aml/aml_export_redaction.patch`. The patch turns the tagged
AML-4 export profile into fixed behavior by removing the linked-case private
note injection and export serialization path while preserving dispute export,
stored export readback, linked public case shells, redaction policy, audit
summaries, EDD summaries, and owner-only note/EDD APIs.

Wave 27 is implemented under review by this handoff only. This does not accept
Wave 27 and does not unlock AML-5 fix work.

## 2. Implementation Details

- `internal/httpapi/export_profile_aml4_vulnerable.go` patch target removes the
  AML-4 tagged call to `FindDuplicatePrivateNotesForPreview` for linked cases.
- `internal/exporting/export_profile_aml4_vulnerable.go` patch target removes
  the AML-4 tagged `bundle.LinkedPrivateNotes` population.
- `internal/httpapi/aml4_vulnerable_export_test.go` patch target replaces the
  vulnerable positive leak test with
  `TestAML4FixedDisputeExportRedactsLinkedPrivateNotesRecursively`.
- The fixed proof test verifies dispute export creation/readback, linked public
  case data, redaction markers, absence of linked private note bodies and EDD
  confidential comments, cross-owner denial, and owner-only note/EDD access.
- No production source file was edited directly; the behavior change exists only
  as the patch artifact.

## 3. Files Changed

- `fixes/sentinel_aml/aml_export_redaction.patch`
- `fixes/sentinel_aml/README.md`
- `docs/wave_reports/wave_27_W27-T01_handoff.md`

## 4. Tests Added

- Added a fixed-profile proof test inside the patch artifact:
  `TestAML4FixedDisputeExportRedactsLinkedPrivateNotesRecursively`.
- No repository test files were modified outside the patch artifact.

## 5. Tests Run

- `git apply --check --whitespace=error fixes/sentinel_aml/aml_export_redaction.patch`:
  exit 0 in the main working tree.
- Temporary patched copy `git apply fixes/sentinel_aml/aml_export_redaction.patch`:
  exit 0.
- Temporary patched copy release/offline no-repo-cache
  `go test -tags aml4_vulnerable ./internal/httpapi -run TestAML4FixedDisputeExportRedactsLinkedPrivateNotesRecursively -count=1 -v`:
  exit 0.
- Temporary patched copy release/offline no-repo-cache `go test ./...`:
  exit 0.
- Temporary patched copy release/offline no-repo-cache `go vet ./...`:
  exit 0.
- Temporary patched copy checker unittest discovery
  `python -B -m unittest discover -s tests -p "test_checker_*.py"`:
  exit 0; 97 tests passed.
- Temporary patched copy `python -B scripts/check_docs_tree.py`:
  exit 0; status `pass`.
- Temporary patched copy `python -B scripts/check_archive_hygiene.py`:
  exit 0; status `pass`.
- Current-tree focused Wave 22 exploit fixture evidence
  `python -B -m unittest discover -s tests -p "test_wave22_gate.py" -k "test_exploit_extracts_flag_from_vulnerable_export_readback"`:
  exit 0; 1 test passed.
- Current-tree focused Wave 22 fixed-output fixture evidence
  `python -B -m unittest discover -s tests -p "test_wave22_gate.py" -k "test_exploit_fails_safely_against_secure_redacted_export"`:
  exit 0; 1 test passed.
- Current-tree `python -B scripts/check_archive_hygiene.py`:
  exit 0; status `pass`.

## 6. Documentation Updated

- Updated `fixes/sentinel_aml/README.md` with the AML-4 fix purpose, scope,
  expected blocked exploit, and anti-coarse-fix warning.
- Added this W27-T01 handoff.

## 7. CTF Invariants Checked

- Place 1 checker GET remains the owner case-note API.
- Place 2 checker GET remains the owner EDD API.
- Export CHECK/HAVOC remains meaningful because dispute export creation,
  export readback, linked public case shells, redaction policy, and public
  summaries remain available.
- Public attack data remains credential-free.
- `sploits/sentinel_aml/aml_export_redaction.py` is blocked by removing only the
  `bundle.linked_private_notes[].body` side-view leak.
- AML-5 fix inventory remains absent.

## 8. Security Invariants Checked

- Fixed export output does not expose linked foreign `CaseNote.body`.
- Fixed export output does not expose `EDDRecord.confidential_comment`,
  `source_of_funds`, `risk_rationale`, internal evidence comments, audit diffs,
  hashes, credentials, sessions, debug/admin output, checker-private state, or
  raw DB rows.
- Owner private notes and owner EDD confidential comments remain reachable only
  through their owner APIs.

## 9. Self-Review

The patch is narrow and AML-4-only. It does not remove export/dispute endpoints,
does not modify checker behavior, does not alter accepted exploits, does not
change public attack-data schema, and does not touch AML-1, AML-2, AML-3, or
AML-5 patch semantics. The behavior remains represented as a patch artifact,
not as direct product-source edits.

## 10. Risks / Open Questions

- This task provides the AML-4 reference fix artifact and proof evidence only;
  Wave 27 still needs the later gate/matrix/documentation tasks and orchestrator
  review.
- No `wave27-gate` exists yet in this task scope.
- AML-5 fix work remains locked until its wave opens.

## 11. Ready for Orchestrator Review

Yes.
