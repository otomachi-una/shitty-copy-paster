# Wave 29 Validation Summary

## Status

Wave 29 is implemented under review and ready for orchestrator re-review. This
summary records W29-T01 full competition matrix evidence, W29-T02 end-to-end
regression evidence, W29-T03 documentation/status reconciliation, and W29-F01
aggregate gate liveness stabilization. The first orchestrator review marked
Wave 29 `needs fixes` because `timeout 300 make wave29-gate` timed out; W29-F01
then produced exact aggregate gate success evidence. This summary does not
self-accept Wave 29 and does not mark final competition readiness; Wave 30
packaging and release validation remain locked until orchestrator acceptance.

## Matrix Evidence

- Vulnerable-checker cells are concrete for AML-1 through AML-5 through the
  accepted tagged vulnerable profiles and competition matrix gate.
- Exploit-success cells are concrete for all five accepted reference sploits:
  `aml_dedup_preview.py`, `aml_audit_timeline.py`, `aml_related_graph.py`,
  `aml_export_redaction.py`, and `aml_network_room.py`.
- Fixed-checker, exploit-blocked, and anti-coarse-fix cells are concrete for
  all five reference fixes:
  `fixes/sentinel_aml/aml_dedup_preview.patch`,
  `fixes/sentinel_aml/aml_audit_timeline.patch`,
  `fixes/sentinel_aml/aml_related_graph.patch`,
  `fixes/sentinel_aml/aml_export_redaction.patch`, and
  `fixes/sentinel_aml/aml_network_room.patch`.
- `scripts/check_competition_matrix_gate.py` validates all five exploit and
  fix rows together.
- `scripts/check_wave29_gate.py` validates full-matrix wiring, checker
  invariants, exact exploit/fix inventory, patch applicability, focused
  vulnerable tag package coverage, and anti-coarse-fix evidence.
- `scripts/check_wave29_regression.py` validates checker PUT/GET and
  CHECK/HAVOC regression, all five sploit compiles, all five vulnerable build
  tags, and cumulative clean-copy patch application with focused fixed proofs.

## W29-F01 Gate Liveness Evidence

W29-F01 replaced the five duplicate full tagged `go test ./...` sweeps in
`wave29-gate` with focused release/offline package checks:

- AML-1 and AML-2: `./internal/httpapi`;
- AML-3: `./internal/httpapi ./internal/graph`;
- AML-4: `./internal/httpapi ./internal/exporting`;
- AML-5: `./internal/httpapi ./internal/networkroom`.

This preserves vulnerable-profile evidence because those packages contain the
tagged vulnerable code and proof tests for each AML profile. The gate still
runs the full untagged package-by-package release/offline Go runner, Go vet,
checker tests, matrix tests, all sploit compiles, all patch apply checks,
Wave 29 static validation, Wave 29 regression validation, docs-tree, ForcAD,
and archive hygiene.

The Wave 29 regression runner now prints per-section progress with elapsed
seconds and creates temporary patched checkouts on a native `/mnt/c` parent
when invoked from WSL with Windows `go.exe`, avoiding `\\wsl.localhost` Go
locking failures.

Command evidence from W29-F01:

- `python -B -m unittest discover -s tests -p "test_wave29_gate.py"` - exit 0,
  11 tests passed, elapsed about 5.0 seconds.
- `python -B -m unittest discover -s tests -p "test_wave29_regression.py"` -
  exit 0, 5 tests passed, elapsed about 0.4 seconds.
- `python -B -m unittest discover -s tests -p "test_run_go_release_tests.py"` -
  exit 0, 2 tests passed, elapsed about 0.8 seconds.
- `timeout 300 make wave29-gate` - exit 0 through the GNU/WSL review path,
  elapsed about 202 seconds.
- `python -B scripts/check_archive_hygiene.py` - exit 0 after the aggregate
  gate.

Evidence was not removed. The duplicate full tagged sweeps were replaced with
equivalent focused package coverage, while the full untagged release runner and
end-to-end regression evidence remain in the aggregate gate.

## Remaining Wave 30 Scope

Wave 30 must still perform final packaging and release validation before any
competition-readiness claim. Remaining scope includes source-of-truth freeze,
archive hygiene, ForcAD validation, package reproducibility, full matrix and
regression reruns, and final release-candidate handoff.

## Invariants Preserved

- Checker PFR still has two places: `CaseNote.body` and
  `EDDRecord.confidential_comment`.
- Public attack data remains credential-free and raw-flag-free.
- Reference sploits use normal public side-view business flows, not owner APIs
  or direct database paths.
- Reference fixes preserve business functionality while blocking their matched
  exploit.
- Fixed builds preserve projection allowlists, recursive redaction, and
  reference-only network-room dossier semantics.
- Debug/admin shortcuts, direct DB checker paths, broad serialization, and
  sensitive-field rename leaks remain forbidden.

## Known Limitations

- Wave 29 is not accepted by this summary; orchestrator review must decide.
- Final packaging and release-candidate reproducibility remain Wave 30 work.
