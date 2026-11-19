# W25-T03 Handoff - AML-2 Exploit-Blocked and Anti-Coarse-Fix Evidence

## 1. Summary

Strengthened Wave 25 AML-2 validation evidence. The tests now prove the
accepted AML-2 exploit succeeds against the vulnerable audit timeline fixture,
fails safely against redacted fixed timeline output, and that the fixed fixture
preserves event existence, redaction markers, and owner note access.

## 2. Implementation Details

- Extended `tests/test_wave25_gate.py` with a fixed AML-2 timeline fixture that
  returns a `case_note` audit event with `case_note.body`, `[redacted]`, and
  `redacted: true`.
- Verified `aml_audit_timeline.py` fails safely against that redacted fixed
  timeline output without calling `/api/cases/{case_id}/notes`.
- Added owner-note fixture evidence showing the private note remains available
  through the owner note path, not through audit side-view output.
- Extended `scripts/check_wave25_gate.py` so anti-coarse-fix checks reject
  removal of `/activity` routes as well as `/timeline`, audit creation, and
  owner note path removals.
- Added a Wave 25 test that rejects patches removing `/activity`.
- Existing docs-only and gate-constant-only negative tests remain in place.

## 3. Files Changed

- `scripts/check_wave25_gate.py`
- `tests/test_wave25_gate.py`
- `docs/wave_reports/wave_25_W25-T03_handoff.md`

## 4. Tests Added

- AML-2 exploit succeeds against vulnerable fixture.
- AML-2 exploit fails safely against redacted fixed timeline output.
- Fixed output preserves event existence and redaction markers.
- Owner note GET remains reachable for owner-only access.
- Coarse patch rejection for `/activity` removal.

## 5. Tests Run

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

## 6. Documentation Updated

Created this W25-T03 handoff with exploit-blocked and anti-coarse-fix evidence.

## 7. CTF Invariants Checked

- Audit CHECK/HAVOC remains meaningful because fixed output still exposes audit
  event existence and redaction markers.
- Owner note GET remains unchanged in scope and is not used by the exploit.
- Public attack data stays credential-free.
- AML-3 through AML-5 reference fixes remain absent.

## 8. Security Invariants Checked

- No raw sensitive field value appears in the fixed audit side-view fixture.
- `CaseNote.body` remains visible only through owner note APIs.
- The gate rejects debug/admin shortcuts, direct DB access, shell execution,
  audit disablement, timeline removal, and activity removal.

## 9. Self-Review

The change is evidence-only. It does not alter production behavior, checker
code, accepted exploit scripts, public attack data, migrations, deployment
files, or any AML-3 through AML-5 fix artifact.

## 10. Risks / Open Questions

- The fixed-output proof is a deterministic Python fixture; full patched Go
  behavior remains covered by the W25-T01 patch evidence and by the Wave 25
  gate's static patch checks.

## 11. Ready for Orchestrator Review

Yes.
