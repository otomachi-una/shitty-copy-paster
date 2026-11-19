# W24-T01 Handoff - AML-1 Narrow Reference Fix Artifact

## 1. Summary

Created the AML-1 reference fix artifact for the dedup merge-preview leak. The
patch makes the `aml1_vulnerable` build return the safe public duplicate-preview
projection, so `aml_dedup_preview.py` can no longer read
`candidate.private_notes[].body`, while duplicate discovery and merge-preview
public fields remain available.

## 2. Implementation Details

- Added `fixes/sentinel_aml/aml_dedup_preview.patch`.
- The patch removes the AML-1 vulnerable private-note preview DTOs and the
  `FindDuplicatePrivateNotesForPreview` serialization path from
  `internal/httpapi/dedup_profile_aml1_vulnerable.go`.
- The patched tagged profile returns `CaseDuplicateMergePreviewResponse` with
  `duplicatePreviewView(candidate)`, matching the secure projection.
- The patch updates the AML-1 tagged Go test to assert the fixed merge-preview
  shape omits `private_notes`, `body`, foreign note sentinels, EDD confidential
  comments, audit/diff markers, credential/session markers, and owner-private
  identifiers while retaining the candidate public summary and case id.

## 3. Files Changed

- `fixes/sentinel_aml/aml_dedup_preview.patch`
- `fixes/sentinel_aml/README.md`
- `docs/wave_reports/wave_24_W24-T01_handoff.md`

## 4. Tests Added

- The patch updates the AML-1 tagged dedup test from leak-positive behavior to
  fixed-profile behavior:
  `TestAML1FixedDedupMergePreviewUsesPublicProjection`.

## 5. Tests Run

| Command | Result |
| --- | --- |
| `git apply --check fixes\sentinel_aml\aml_dedup_preview.patch` | exit 0 |
| `git apply --check --whitespace=error fixes\sentinel_aml\aml_dedup_preview.patch` | exit 0 |
| `git apply C:\Users\2005g\GolandProjects\Sentinel_AML\fixes\sentinel_aml\aml_dedup_preview.patch` in temp repo copy | exit 0 |
| patched temp copy: `go test ./...` with `GOTOOLCHAIN=local`, `GOFLAGS=-mod=vendor`, `GOTELEMETRY=off`, temp `GOCACHE` | exit 0 |
| patched temp copy: `go test -tags aml1_vulnerable ./internal/httpapi -run TestAML1FixedDedupMergePreviewUsesPublicProjection -count=1` | exit 0 |
| patched temp copy: `go test -tags aml1_vulnerable ./internal/httpapi -count=1` | exit 0 |
| patched temp copy: `python -B -m unittest discover -s tests -p "test_checker_*.py"` | exit 0; 97 tests passed |
| patched temp copy: `python -B -m unittest discover -s tests -p "test_wave19_gate.py" -k "test_exploit_fails_safely_against_secure_preview"` | exit 0; proves original `aml_dedup_preview.py` exits non-zero when `private_notes` is absent |
| main artifact tree: `python -B scripts\check_docs_tree.py` | exit 0; status `pass` |
| main artifact tree: `python -B scripts\check_archive_hygiene.py` | exit 0; status `pass` |

## 6. Documentation Updated

- `fixes/sentinel_aml/README.md` now documents the AML-1 fix purpose, scope,
  expected blocked exploit, and anti-coarse-fix warning.
- This handoff records W24-T01 implementation evidence for orchestrator review.

## 7. CTF Invariants Checked

- Place 1 PUT/GET remains the owner-only case-note API:
  `GET /api/cases/{case_id}/notes`.
- CHECK/HAVOC dedup behavior still has duplicate candidates and public
  merge-preview fields.
- Public attack data remains credential-free and raw-flag-free.
- No AML-2, AML-3, AML-4, or AML-5 fix is added.

## 8. Security Invariants Checked

- Foreign `CaseNote.body` is removed from dedup merge-preview output.
- Owner private notes remain available only through owner case-note APIs.
- EDD confidential comments, audit diffs, internal evidence, credentials,
  sessions, debug/admin paths, shell/subprocess paths, and direct DB paths are
  not introduced or normalized.

## 9. Self-Review

The artifact is narrow: it changes only the tagged AML-1 projection and its
tagged proof test inside the patch. It does not remove deduplication, alter
checker behavior, add migration/config changes, or touch other vulnerabilities.

## 10. Risks / Open Questions

- Wave 23 gates intentionally reject fix artifacts; they should not be used as
  Wave 24 acceptance gates without a Wave 24-aware update.
- The exploit-block proof uses the existing secure-preview fake service path
  that omits `candidate.private_notes`, matching the patched projection. It does
  not run the exploit against a live patched Docker service.

## 11. Ready for Orchestrator Review

Yes.
