# W20-T01 Handoff - AML-2 Audit Timeline Reference Exploit

## 1. Summary

Implemented the Wave 20 AML-2 reference exploit
`sploits/sentinel_aml/aml_audit_timeline.py`. The exploit is a standalone
stdlib Python script that accepts host, port, and public attack-info JSON or a
JSON file; registers and logs in as an attacker; requests the normal case
timeline side view; and prints only a flag-like token extracted from the
vulnerable `case_note.body` audit change.

Wave 20 is ready for orchestrator review but is not marked accepted by this
handoff. No reference fix was added.

## 2. Implementation Details

- Added a resilient `urllib.request` HTTP client with explicit timeouts and
  concise failure errors.
- Added public attack-info validation for `sentinel_aml`, place 1
  `CaseNote.body`, `case_id`, and locator metadata such as `customer_id`,
  `dedup_hint`, or `typology_hint`.
- Added deterministic attacker registration/login helpers using data derived
  from public attack data.
- Added timeline parsing limited to `case_note` events and
  `case_note.body`/`body` changes where `redacted` is explicitly `false`.
- Added optional `diff_json` parsing only as audit diff material; no broad
  response-body scraping is used.
- Kept execution behind `main()` so import has no service side effects.

## 3. Files Changed

- `sploits/sentinel_aml/aml_audit_timeline.py`
- `sploits/sentinel_aml/README.md`
- `scripts/check_wave20_gate.py`
- `tests/test_wave20_gate.py`
- `docs/wave_reports/wave_20_W20-T01_handoff.md`

## 4. Tests Added

- CLI help/import-safety coverage for the exploit module.
- Attack-info validation tests rejecting missing `case_id`, wrong store, and
  missing public locator metadata.
- Fake vulnerable timeline test proving extraction from `changes[].new`.
- Fake vulnerable raw `diff_json` test proving extraction from intended audit
  diff material.
- Fake secure/redacted timeline test proving clean non-zero failure.
- Gate tests rejecting direct database, shell, owner-note-route, public secret
  lookup, import-time execution, AML-3 through AML-5 exploit files, and fix
  artifacts.

## 5. Tests Run

Executed locally on Windows PowerShell from
`C:\Users\2005g\GolandProjects\Sentinel_AML`:

```sh
python -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py
python -B -m unittest discover -s tests -p "test_wave20_gate.py"
python -B scripts/check_wave20_gate.py
python -B scripts/check_competition_matrix_gate.py
```

Results:

| Command | Result |
| --- | --- |
| `python -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py` | exit 0; pass |
| `python -B -m unittest discover -s tests -p "test_wave20_gate.py"` | exit 0; pass; 11 tests |
| `python -B scripts/check_wave20_gate.py` | exit 0; pass |
| `python -B scripts/check_competition_matrix_gate.py` | exit 1; expected W20-T02 follow-up needed because the current matrix gate still encodes Wave 19 one-exploit state and marks `aml_audit_timeline.py` as pending/forbidden |

## 6. Documentation Updated

- `sploits/sentinel_aml/README.md` now lists `aml_audit_timeline.py` as the
  Wave 20 AML-2 reference exploit and keeps AML-3 through AML-5 locked.
- This handoff records scope, tests, invariants, and known risks.

## 7. CTF Invariants Checked

- Checker PUT/GET paths were not modified.
- CHECK/HAVOC behavior was not modified.
- Public attack data remains credential-free.
- The exploit is not a checker dependency.
- `fixes/sentinel_aml/` remains README-only.

## 8. Security Invariants Checked

- The exploit uses only normal HTTP APIs.
- The exploit is bounded to AML-2 case timeline audit diff exposure.
- It does not use direct database access, raw SQL, shell execution,
  debug/admin routes, credential extraction, session theft, graph, export,
  network-room, or EDD side views.

## 9. Self-Review

The implementation follows the accepted AML-1 reference exploit structure but
keeps the AML-2 behavior much narrower: it logs in, reads only
`GET /api/cases/{case_id}/timeline`, and accepts a flag only from an exposed
case-note body audit change. Secure redacted timeline responses return a
non-zero exit with no stdout flag material.

## 10. Risks / Open Questions

- Existing AML-2 product tests document the vulnerable timeline as owner
  scoped. W20-T01 does not modify product code, so live exploitability against
  a deployed tagged profile depends on the orchestrator-confirmed public
  locator route behavior for Wave 20.
- The current competition matrix gate may still encode the Wave 19 state until
  W20-T02 updates matrix validation for the second reference exploit.

## 11. Ready for Orchestrator Review

Yes for W20-T01 reference-exploit review. W20-T02 must update competition
matrix/gate evidence before Wave 20 can be accepted.
