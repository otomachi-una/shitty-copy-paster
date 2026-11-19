# W27-T03 Handoff - AML-4 Exploit-Blocked and Anti-Coarse-Fix Evidence

## 1. Summary

Strengthened Wave 27 AML-4 evidence around exploit-blocked and
anti-coarse-fix behavior. The evidence proves the accepted
`sploits/sentinel_aml/aml_export_redaction.py` exploit parser succeeds on vulnerable output with linked-note leakage and fails safely on fixed output, while export and linked-case public export evidence remain available for CHECK/HAVOC.

Wave 27 remains implemented under review only. This handoff does not accept
Wave 27 and does not unlock AML-5 fix work.

## 2. Implementation Details

- Extended `scripts/check_wave27_gate.py` to reject
  `analyst_internal_note`/`AnalystInternalNote` style sensitive-field renames in
  fixed export output.
- Added a gate documentation check for this W27-T03 handoff.
- Strengthened `tests/test_wave27_gate.py` with a negative case that fails when
  the AML-4 patch removes linked-case public export evidence from the fixed
  proof shape.
- Strengthened the fixed export fixture assertion to ensure
  `analyst_internal_note` is absent from public export output.
- Preserved existing tests for docs-only patches, gate-only patches,
  export/dispute endpoint deletion, export builder deletion, raw
  `CaseNote.body` reintroduction, EDD confidential comment leakage, audit
  diffs, hashes, direct DB shortcuts, debug/admin paths, shell helpers, and
  export disablement.

## 3. Files Changed

- `scripts/check_wave27_gate.py`
- `tests/test_wave27_gate.py`
- `docs/wave_reports/wave_27_W27-T03_handoff.md`

## 4. Tests Added

- `test_patch_blocks_leak_rejects_sensitive_renames_hashes_and_raw_diffs` now
  includes `AnalystInternalNote string \`json:"analyst_internal_note"\`` as an
  explicitly rejected fixed-output field.
- `test_patch_anti_coarse_fix_rejects_deletion_of_linked_public_export_evidence`
  rejects a patch proof that drops `AML4 linked public shell`, `linked_cases`,
  or `sensitive_field` evidence from the fixed export contract.
- Fixed export fixture assertions now verify `analyst_internal_note` is absent
  from public export payloads.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_wave27_gate.py"`:
  exit 0, 23 tests.
- `python -B scripts/check_wave27_gate.py`: exit 0, JSON status `pass`.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`:
  exit 0, 97 tests.
- `python -B scripts/check_competition_matrix_gate.py`: exit 0, JSON status
  `pass`.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  exit 0, 31 tests.
- `python -B scripts/check_docs_tree.py`: exit 0, JSON status `pass`.
- `python -B scripts/check_archive_hygiene.py`: exit 0, JSON status `pass`.
- `timeout 300 make wave27-gate`: exit 1 on this Windows host before invoking
  `make`; Windows `timeout` reported `Invalid syntax`.

## 6. Documentation Updated

- Created this W27-T03 handoff with exploit-blocked and anti-coarse-fix
  evidence.

## 7. CTF Invariants Checked

- Export CHECK/HAVOC remains strong because fixed output must retain root and
  linked public case shells, `linked_cases`, `redaction_policy`, and
  `sensitive_field` evidence.
- AML-4 exploit success remains documented against vulnerable
  `bundle.linked_private_notes[].body` output only.
- Prior fixes and all five accepted exploits remain untouched.

## 8. Security Invariants Checked

- Fixed export output must remain recursive-public/redacted for linked cases.
- The gate rejects raw linked foreign `CaseNote.body`,
  `EDDRecord.confidential_comment`, `analyst_internal_note`,
  `internal_comment`, audit diffs, hashes, renamed equivalent fields,
  credentials, sessions, checker-private shortcuts, debug/admin paths, direct
  DB shortcuts, and shell helpers.

## 9. Self-Review

The changes are limited to Wave 27 validation/evidence and this handoff. I did
not edit exploit scripts, product source, checker code, patch semantics,
competition matrix status, Makefile, or AML-5 fix inventory. The added coverage
targets exactly the T03 evidence gaps rather than broadening the fix.

## 10. Risks / Open Questions

- The evidence remains static plus fixture-based in this task; aggregate runtime
  validation is still carried by `wave27-gate` from W27-T02.
- Local Windows `timeout` is not GNU-compatible, so the exact
  `timeout 300 make wave27-gate` wrapper could not be proven here even though
  the Wave 27 unit gate, checker tests, matrix gate, docs tree, and archive
  hygiene checks passed.

## 11. Ready for Orchestrator Review: yes

Yes, with the local Windows wrapper caveat recorded above.
