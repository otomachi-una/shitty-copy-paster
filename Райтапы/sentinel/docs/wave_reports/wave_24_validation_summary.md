# Wave 24 Validation Summary

## Status

Wave 24 is blocked pending exact aggregate-gate re-review. W24-F01 implements
the gate-liveness fix, but Wave 24 is not accepted until
`timeout 300 make wave24-gate` exits 0 on a make-equipped orchestrator review
host. Wave 23 is accepted, Wave 25 is not started, and W25-W28 reference fix
waves remain locked.

## Scope

Wave 24 adds the first reference fix artifact only:
`fixes/sentinel_aml/aml_dedup_preview.patch`.

The current reference exploit set remains exactly:

- `sploits/sentinel_aml/aml_dedup_preview.py`
- `sploits/sentinel_aml/aml_audit_timeline.py`
- `sploits/sentinel_aml/aml_related_graph.py`
- `sploits/sentinel_aml/aml_export_redaction.py`
- `sploits/sentinel_aml/aml_network_room.py`

The current reference fix set contains only AML-1. No AML-2, AML-3, AML-4, or
AML-5 fix artifact is implemented.

## W24-T01 Evidence

W24-T01 added `fixes/sentinel_aml/aml_dedup_preview.patch` and updated
`fixes/sentinel_aml/README.md`. The patch restores the public
`CaseDuplicateMergePreviewResponse` projection in the `aml1_vulnerable`
profile by removing private note preview DTOs and the
`FindDuplicatePrivateNotesForPreview` serialization path.

Recorded W24-T01 checks:

- `git apply --check fixes\sentinel_aml\aml_dedup_preview.patch`: exit 0
- `git apply --check --whitespace=error fixes\sentinel_aml\aml_dedup_preview.patch`: exit 0
- patched temp copy `go test ./...`: exit 0
- patched temp copy `go test -tags aml1_vulnerable ./internal/httpapi -count=1`: exit 0
- patched temp copy checker tests: exit 0; 97 tests passed
- original AML-1 exploit secure-output failure proof: exit 0

## W24-T02 Evidence

W24-T02 added `scripts/check_wave24_gate.py`, Wave 24 gate tests, the
`wave24-gate` Makefile target, and competition matrix alignment. The matrix now
marks AML-1 fixed-checker, exploit-blocked, and anti-coarse-fix cells concrete
while AML-2 through AML-5 fix cells remain pending.

Recorded W24-T02 checks:

- `python -B scripts\check_wave24_gate.py`: exit 0; status `pass`
- `python -B scripts\check_competition_matrix_gate.py`: exit 0; status `pass`
- `python -B -m unittest discover -s tests -p "test_wave24_gate.py"`: exit 0;
  10 tests passed at W24-T02 time
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  exit 0; 28 tests passed
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`: exit 0;
  97 tests passed
- release/offline `go test ./...`: exit 0
- release/offline `go vet ./...`: exit 0
- no-repo-cache `py_compile` for all five exploits: exit 0
- `make wave24-gate`: not runnable in the local Windows shell because `make`
  was not installed

## W24-T03 Evidence

W24-T03 strengthened exploit-blocked and anti-coarse-fix evidence. Wave 24 tests
now prove the accepted `aml_dedup_preview.py` exploit succeeds against a
vulnerable fixture with `candidate.private_notes[].body`, fails safely against
fixed public merge-preview output, and rejects endpoint-removal,
dedup-disablement, docs-only, and gate-only patch shapes.

Recorded W24-T03 checks:

- `python -B scripts\check_wave24_gate.py`: exit 0; status `pass`
- `python -B scripts\check_competition_matrix_gate.py`: exit 0; status `pass`
- `python -B -m unittest discover -s tests -p "test_wave24_gate.py"`: exit 0;
  15 tests passed
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  exit 0; 28 tests passed
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`: exit 0;
  97 tests passed
- release/offline `go test ./...`: exit 0
- release/offline `go vet ./...`: exit 0
- no-repo-cache `py_compile` for all five exploits: exit 0
- `python -B scripts\check_docs_tree.py`: exit 0; status `pass`
- `python -B scripts\validate_forcad_config.py`: exit 0
- `python -B scripts\check_archive_hygiene.py`: exit 0; status `pass`
- `make wave24-gate`: not runnable in the local Windows shell because `make`
  was not installed

## W24-F01 Evidence

W24-F01 stabilizes the Wave 24 aggregate gate liveness after orchestrator
evidence showed `timeout 300 make wave24-gate` reaching the release/offline
`go test ./...` step and then being terminated by the outer timeout. Component
commands were already passing, so the fix keeps product behavior untouched and
changes only gate execution shape.

The Wave 24 target now runs the release/offline Go test step with isolated
temporary `GOCACHE` and `APPDATA` paths, serial package execution, no cached
test results, and an explicit Go test timeout:

- `GOCACHE=$(mktemp -d "${TMPDIR:-/tmp}/sentinel-aml-gocache.XXXXXXXXXX")`
- `APPDATA=$(mktemp -d "${TMPDIR:-/tmp}/sentinel-aml-appdata.XXXXXXXXXX")`
- `go test -p 1 -timeout 120s -count=1 ./...`

The Wave 24 gate checker and tests now reject the old unbounded
`$(GO_RELEASE_ENV) $(GO) test ./...` recipe and reject shared release cache
paths.

Recorded W24-F01 checks:

- `python -B -m unittest discover -s tests -p "test_wave24_gate.py"`: exit 0;
  17 tests passed
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  exit 0; 28 tests passed
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`: exit 0;
  97 tests passed
- `python -B scripts\check_wave24_gate.py`: exit 0; status `pass`
- `python -B scripts\check_competition_matrix_gate.py`: exit 0; status `pass`
- `python -B scripts\check_archive_hygiene.py`: exit 0; status `pass`
- `python -B scripts\check_docs_tree.py`: exit 0; status `pass`
- `python -B scripts\validate_forcad_config.py`: exit 0
- no-repo-cache `py_compile` for all five exploits: exit 0
- `git apply --check --whitespace=error fixes/sentinel_aml/aml_dedup_preview.patch`:
  exit 0
- release/offline no-repo-cache `go test -p 1 -timeout 120s -count=1 ./...`:
  exit 0
- release/offline no-repo-cache `go vet ./...`: exit 0
- exact aggregate wrapper evidence remains pending on a POSIX make-equipped
  review host; local `bash.exe -lc "timeout 300 make wave24-gate"` exited 1
  because WSL bash startup returned `E_ACCESSDENIED`
- `where.exe make`: exit 1; no local `make` executable is installed on this
  Windows host

## W24-F02 Status Reconciliation

W24-F02 reconciles the ledgers after W24-F01 without fabricating acceptance
evidence. The decision basis is that W24-F01 component evidence is green, but
the exact aggregate command required for Wave 24 acceptance has not yet
produced an exit-0 result after the liveness fix. Therefore Wave 24 remains
blocked pending exact aggregate-gate re-review, and Wave 25 remains locked.

## CTF Invariants

- Place 1 checker GET remains `GET /api/cases/{case_id}/notes`.
- Place 2 checker GET remains `GET /api/customers/{customer_id}/edd`.
- Strong CHECK/HAVOC remains release-blocking through checker tests in
  `wave24-gate`.
- Public attack data remains credential-free and raw-flag-free.
- Dedup candidate discovery and merge-preview remain available with public
  fields.

## Security Invariants

- Fixed AML-1 merge-preview is public-only.
- Foreign `CaseNote.body` is not visible through merge-preview after the fix.
- Owner private notes remain visible only through owner case-note APIs.
- EDD confidential comments, internal evidence, audit diffs, debug/admin paths,
  direct DB shortcuts, shell/subprocess primitives, broad serialization, and
  cross-vulnerability chaining remain out of scope.

## Known Limitations

- Wave 24 is blocked pending exact aggregate-gate re-review, not accepted.
- `timeout 300 make wave24-gate` requires a make-equipped review host; local
  evidence used component commands because `make` was unavailable in this
  Windows shell and WSL bash startup returned `E_ACCESSDENIED`.
- W25-W28 remain locked.
