# Wave 27 Validation Summary

## Status

Wave 27 is implemented under review. It is not accepted by agent
documentation. Wave 28 remains locked until Wave 27 orchestrator acceptance.

## Scope

Wave 27 adds exactly the AML-4 reference fix sequence:

- W27-T01 created `fixes/sentinel_aml/aml_export_redaction.patch`.
- W27-T02 added `scripts/check_wave27_gate.py`, `tests/test_wave27_gate.py`,
  `wave27-gate`, and competition matrix alignment.
- W27-T03 strengthened exploit-blocked and anti-coarse-fix evidence.
- W27-T04 aligns active documentation/status ledgers.
- W27-F01 stabilized the package-by-package release/offline Go runner with
  child-process cleanup and stuck-package regression coverage after the first
  aggregate review reported a liveness blocker.
- W27-F02 reconciles status ledgers after W27-F01 without claiming acceptance
  because no exact exit-0 `timeout 300 make wave27-gate` evidence is present in
  this workspace.

No product source, checker behavior, exploit scripts, public attack-data schema,
migrations, deployment files, accepted AML-1/AML-2/AML-3 patch semantics, or
AML-5 fix artifact is changed by the documentation alignment.

## Evidence

The AML-4 patch is narrow to the tagged export vulnerable profile/proof files
and restores recursive public export redaction for linked cases. The evidence
requires:

- `git apply --check --whitespace=error fixes/sentinel_aml/aml_export_redaction.patch`
  success;
- patched Go tests and Go vet success recorded in W27-T01;
- `aml_export_redaction.py` succeeds only on vulnerable output containing
  `bundle.linked_private_notes[].body`;
- fixed export output keeps export/dispute functionality, stored export
  readback, linked public case summaries, `linked_cases`, `redaction_policy`,
  and `sensitive_field` evidence;
- fixed export output omits linked foreign `CaseNote.body`,
  `EDDRecord.confidential_comment`, `analyst_internal_note`,
  `internal_comment`, raw audit diffs, hashes, credentials, sessions,
  checker-private state, debug/admin data, and raw DB rows;
- gate tests reject docs-only patches, gate-only patches, endpoint-removal
  fixes, export disablement, linked public evidence deletion, direct DB
  shortcuts, and shell helpers.
- W27-F01 runner evidence shows
  `python -B scripts/run_go_release_tests.py --go go --package-timeout 120`
  exited 0 locally and runner tests cover bounded stuck-package failure. The
  exact GNU-style `timeout 300 make wave27-gate` wrapper still requires
  orchestrator-host verification before Wave 27 can be accepted.

## Competition Matrix

Current branch matrix state:

- AML-1 through AML-5 vulnerable-checker cells are concrete.
- AML-1 through AML-5 exploit-success cells are concrete.
- AML-1 through AML-4 fixed-checker, exploit-blocked, and anti-coarse-fix cells
  are concrete in the gate.
- AML-5 fixed-checker, exploit-blocked, and anti-coarse-fix cells remain
  pending.

Competition readiness remains incomplete until the AML-5 reference fix, full
regression matrix, packaging, and final validation pass.

## Known Limitations

- Wave 27 remains under review until exact aggregate-gate acceptance evidence
  exists.
- Wave 28 and the AML-5 reference fix remain locked.
- Local Windows validation may not run the exact GNU-style
  `timeout 300 make wave27-gate` wrapper because Windows `timeout` and missing
  `make` can fail before project code executes; W27-F01 records the same local
  wrapper caveat after stabilizing the runner itself.
