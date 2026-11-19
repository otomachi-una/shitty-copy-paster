# Wave 25 Validation Summary

## Status

Wave 25 is implemented under review. This agent documentation does not accept
Wave 25 and does not unlock Wave 26; orchestrator review is required before the
AML-3 reference-fix wave can start.

Wave 24 is complete as the prerequisite for the current Wave 25 sequence. Wave
23 remains accepted, and the five reference exploit scripts remain concrete.

## Scope

Wave 25 adds the second reference fix artifact only:
`fixes/sentinel_aml/aml_audit_timeline.patch`.

The current reference exploit set remains exactly:

- `sploits/sentinel_aml/aml_dedup_preview.py`
- `sploits/sentinel_aml/aml_audit_timeline.py`
- `sploits/sentinel_aml/aml_related_graph.py`
- `sploits/sentinel_aml/aml_export_redaction.py`
- `sploits/sentinel_aml/aml_network_room.py`

The current reference fix set contains exactly:

- `fixes/sentinel_aml/aml_dedup_preview.patch`
- `fixes/sentinel_aml/aml_audit_timeline.patch`

No AML-3, AML-4, or AML-5 reference fix artifact is implemented.

## W25-T01 Evidence

W25-T01 added `fixes/sentinel_aml/aml_audit_timeline.patch` and updated the
reference-fix README. The patch removes the AML-2 tagged timeline behavior that
re-expanded redacted audit diffs into raw `CaseNote.body` values. It preserves
audit event existence, redacted `case_note.body` field evidence, timeline
functionality, and owner note access through `GET /api/cases/{case_id}/notes`.

Recorded W25-T01 checks:

- `git apply --check --whitespace=error fixes\sentinel_aml\aml_audit_timeline.patch`:
  exit 0 in the main working tree.
- Temporary patched copy `git apply --check --whitespace=error`: exit 0.
- Temporary patched copy `go test ./...`: exit 0.
- Temporary patched copy
  `go test -tags aml2_vulnerable ./internal/httpapi -run TestAML2FixedAuditTimelineRedactsCaseNoteBody -count=1 -v`:
  exit 0.
- Temporary patched copy
  `go test -tags aml2_vulnerable ./internal/httpapi -count=1`: exit 0.
- Temporary patched copy checker tests: exit 0; 97 tests passed.
- Temporary patched copy `go vet ./...`: exit 0.
- Accepted exploit parser against fixed redacted timeline shape: exit 0 with
  `{"values": [], "blocked": true}`.

## W25-T02 Evidence

W25-T02 added `scripts/check_wave25_gate.py`, Wave 25 gate tests, the
`wave25-gate` Makefile target, and competition matrix alignment. The matrix now
marks AML-1 and AML-2 fixed-checker, exploit-blocked, and anti-coarse-fix cells
concrete while AML-3 through AML-5 fix cells remain pending.

Recorded W25-T02 checks:

- `python -B scripts/check_wave25_gate.py`: exit 0.
- `python -B scripts/check_competition_matrix_gate.py`: exit 0.
- `python -B -m unittest discover -s tests -p "test_wave25_gate.py"`:
  exit 0; 14 tests passed at W25-T02 time.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  exit 0; 29 tests passed.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`:
  exit 0; 97 tests passed.
- No-repo-cache `python -B -m py_compile` for all five Sentinel AML exploits:
  exit 0.
- `git apply --check --whitespace=error fixes/sentinel_aml/aml_dedup_preview.patch`:
  exit 0.
- `git apply --check --whitespace=error fixes/sentinel_aml/aml_audit_timeline.patch`:
  exit 0.
- Release/offline no-repo-cache
  `go test -p 1 -timeout 120s -count=1 ./...`: exit 0.
- Release/offline no-repo-cache `go vet ./...`: exit 0.
- `python -B scripts/check_docs_tree.py`: exit 0.
- `python -B scripts/validate_forcad_config.py`: exit 0.
- `python -B scripts/check_archive_hygiene.py`: exit 0.
- `make wave25-gate`: not runnable in the local Windows shell because no
  `make`, `mingw32-make`, or `gmake` executable is available on PATH.

## W25-T03 Evidence

W25-T03 strengthened exploit-blocked and anti-coarse-fix evidence. Wave 25 tests
now prove `aml_audit_timeline.py` succeeds against vulnerable fixture output,
fails safely against fixed redacted timeline output, and that fixed output
preserves event existence, redaction markers, and owner note access. The gate
also rejects `/timeline` removal, `/activity` removal, audit-disablement,
docs-only, gate-only, and raw-body reintroduction patch shapes.

Recorded W25-T03 checks:

- `python -B -m unittest discover -s tests -p "test_wave25_gate.py"`:
  exit 0; 16 tests passed.
- `python -B scripts/check_wave25_gate.py`: exit 0.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  exit 0; 29 tests passed.
- `python -B scripts/check_competition_matrix_gate.py`: exit 0.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`:
  exit 0; 97 tests passed.
- `python -B scripts/check_docs_tree.py`: exit 0.
- `python -B scripts/validate_forcad_config.py`: exit 0.
- `python -B scripts/check_archive_hygiene.py`: exit 0.

## CTF Invariants

- Place 1 checker GET remains `GET /api/cases/{case_id}/notes`.
- Place 2 checker GET remains `GET /api/customers/{customer_id}/edd`.
- Strong CHECK/HAVOC remains release-blocking through checker tests in
  `wave25-gate`.
- Public attack data remains credential-free and raw-flag-free.
- Audit timeline functionality remains available with redacted field evidence.

## Security Invariants

- Fixed AML-2 audit side-view output is redacted and contains no raw
  `CaseNote.body` value.
- Owner private notes remain visible only through owner case-note APIs.
- EDD confidential comments, internal evidence, raw audit `diff_json`,
  debug/admin paths, direct DB shortcuts, shell/subprocess primitives, broad
  serialization, endpoint-removal fixes, and cross-vulnerability chaining
  remain out of scope.

## Known Limitations

- Wave 25 is implemented under review, not accepted.
- Wave 26 remains locked until Wave 25 orchestrator acceptance.
- Local `make wave25-gate` evidence remains unavailable on this Windows host
  because no make-compatible executable is installed; component commands are
  recorded in W25-T02.
