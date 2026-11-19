# W25-T01 Handoff - AML-2 Narrow Reference Fix Artifact

## 1. Summary

Created the AML-2 reference fix artifact
`fixes/sentinel_aml/aml_audit_timeline.patch`. The patch removes the AML-2
tagged timeline behavior that re-expanded redacted audit diffs into raw
`CaseNote.body` values, while keeping timeline events and owner note access
available.

## 2. Implementation Details

- The patch targets only `internal/httpapi/audit_profile_aml2_vulnerable.go`
  and `internal/httpapi/aml2_vulnerable_audit_test.go`.
- Fixed AML-2 timeline projection preserves audit event existence and the
  `case_note.body` field identifier.
- Fixed `old` and `new` values remain redacted and `redacted` remains `true`.
- The vulnerable lookup path that called `ListNotesByOwner` solely to repopulate
  timeline diff values is removed from the side-view projection.
- The tagged proof test now verifies redaction, public timeline functionality,
  cross-owner fail-closed behavior, export/network non-broadening, and owner
  note API availability.

## 3. Files Changed

- `fixes/sentinel_aml/aml_audit_timeline.patch`
- `fixes/sentinel_aml/README.md`
- `docs/wave_reports/wave_25_W25-T01_handoff.md`

## 4. Tests Added

The patch artifact updates the AML-2 tagged Go test in the patched copy:
`TestAML2FixedAuditTimelineRedactsCaseNoteBody`.

## 5. Tests Run

- `git apply --check --whitespace=error fixes\sentinel_aml\aml_audit_timeline.patch`:
  exit 0 in the main working tree.
- Temporary patched copy
  `git apply --check --whitespace=error fixes\sentinel_aml\aml_audit_timeline.patch`:
  exit 0.
- Temporary patched copy `git apply fixes\sentinel_aml\aml_audit_timeline.patch`:
  exit 0.
- Temporary patched copy release/offline `go test ./...`: exit 0.
- Temporary patched copy release/offline
  `go test -tags aml2_vulnerable ./internal/httpapi -run TestAML2FixedAuditTimelineRedactsCaseNoteBody -count=1 -v`:
  exit 0.
- Temporary patched copy release/offline
  `go test -tags aml2_vulnerable ./internal/httpapi -count=1`: exit 0.
- Temporary patched copy `python -B -m unittest discover -s tests -p "test_checker_*.py"`:
  exit 0; 97 tests passed.
- Temporary patched copy release/offline `go vet ./...`: exit 0.
- Accepted exploit parser against fixed redacted timeline shape: exit 0 with
  `{"values": [], "blocked": true}`.
- Repo-local focused exploit safe-failure test
  `python -B -m unittest discover -s tests -p "test_wave20_gate.py" -k exploit_fails_safely_against_secure_redacted_timeline`:
  exit 0; 1 test passed.

## 6. Documentation Updated

Updated `fixes/sentinel_aml/README.md` with AML-2 fix purpose, scope, expected
blocked exploit, and anti-coarse-fix warning.

## 7. CTF Invariants Checked

- Place 1 flag storage remains `CaseNote.body`.
- Checker GET remains owner case notes through `/api/cases/{case_id}/notes`.
- AML-2 exploit is blocked by redaction, not endpoint removal.
- Timeline event existence and redacted change evidence remain available for
  CHECK/HAVOC-style validation.
- No AML-3, AML-4, or AML-5 reference fix artifact was added.

## 8. Security Invariants Checked

- Fixed AML-2 side-view output does not expose raw `CaseNote.body`.
- EDD confidential comments, internal evidence, session tokens, credentials,
  checker-private state, raw `diff_json`, and value hashes remain absent from
  timeline side-view responses.
- No debug/admin endpoint, direct DB shortcut, or checker-only bypass was added.

## 9. Self-Review

The implementation is intentionally narrow: it changes only the AML-2 patch
artifact, reference-fix README, and this handoff. Main repository product code,
checker code, public attack-data schema, accepted exploit scripts, migrations,
deployment files, the AML-1 patch, and AML-3 through AML-5 fixes were not
modified.

## 10. Risks / Open Questions

- The patch preserves `case_note.body` as a field identifier in the timeline
  change response; this is intentional so reviewers can see which field changed
  without exposing values.
- Wave sequencing should still be reconciled by a later gate/status task before
  accepting or unlocking subsequent fix waves.

## 11. Ready for Orchestrator Review

Yes.
