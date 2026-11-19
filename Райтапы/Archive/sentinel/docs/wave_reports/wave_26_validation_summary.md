# Wave 26 Validation Summary

## Status

Wave 26 is implemented under review. This agent documentation does not accept
Wave 26 and does not unlock Wave 27; orchestrator review is required before the
AML-4 reference-fix wave can start.

Wave 25 is accepted as the prerequisite for the current Wave 26 sequence. Wave
23 remains accepted, and the five reference exploit scripts remain concrete.

## Scope

Wave 26 adds the third reference fix artifact only:
`fixes/sentinel_aml/aml_related_graph.patch`.

The current reference exploit set remains exactly:

- `sploits/sentinel_aml/aml_dedup_preview.py`
- `sploits/sentinel_aml/aml_audit_timeline.py`
- `sploits/sentinel_aml/aml_related_graph.py`
- `sploits/sentinel_aml/aml_export_redaction.py`
- `sploits/sentinel_aml/aml_network_room.py`

The current reference fix set contains exactly:

- `fixes/sentinel_aml/aml_dedup_preview.patch`
- `fixes/sentinel_aml/aml_audit_timeline.patch`
- `fixes/sentinel_aml/aml_related_graph.patch`

No AML-4 or AML-5 reference fix artifact is implemented.

## W26-T01 Evidence

W26-T01 added `fixes/sentinel_aml/aml_related_graph.patch` and updated the
reference-fix README. The patch removes the AML-3 tagged graph behavior that
exposed raw `EDDRecord.confidential_comment` through graph EDD summaries. It
preserves graph entity summaries, related-case summaries, EDD-summary side
views, owner EDD APIs, and unrelated export/network-room boundedness checks.

Recorded W26-T01 checks:

- `git apply --check --whitespace=error fixes/sentinel_aml/aml_related_graph.patch`:
  exit 0.
- Temporary patched copy `go test ./...`: exit 0.
- Temporary patched copy focused AML-3 fixed proof test: exit 0.
- Temporary patched copy checker tests: exit 0; 97 tests passed.
- Temporary patched copy `go vet ./...`: exit 0.
- Accepted exploit parser evidence showed vulnerable graph fixture success and
  fixed public graph output safe failure.

## W26-T02 Evidence

W26-T02 added `scripts/check_wave26_gate.py`, Wave 26 gate tests, the
`wave26-gate` Makefile target, and competition matrix alignment. The matrix now
marks AML-1, AML-2, and AML-3 fixed-checker, exploit-blocked, and
anti-coarse-fix cells concrete while AML-4 and AML-5 fix cells remain pending.

Recorded W26-T02 checks:

- `python -B -m unittest discover -s tests -p "test_wave26_gate.py"`:
  exit 0.
- `python -B scripts/check_wave26_gate.py`: exit 0.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  exit 0.
- `python -B scripts/check_competition_matrix_gate.py`: exit 0.
- Checker unittest discovery, docs-tree validation, ForcAD validation, archive
  hygiene, all five exploit compiles, patch-apply checks, bounded
  release/offline Go tests, and Go vet were kept in the aggregate gate.
- `timeout 300 make wave26-gate` was not runnable on this local Windows host
  because no make-compatible executable is installed on PATH.

## W26-T03 Evidence

W26-T03 strengthened exploit-blocked and anti-coarse-fix evidence. Wave 26 tests
now prove `aml_related_graph.py` succeeds against vulnerable graph EDD-summary
fixture output, fails safely against fixed public graph output, and that fixed
output preserves public graph/event evidence and owner EDD access. The gate also
rejects `/edd-summaries` removal, `/related-cases` removal, graph repository or
test deletion, docs-only patches, gate-only patches, renamed private-field
leaks, hash/raw-diff leaks, debug/admin paths, direct DB shortcuts, and shell
helpers.

Recorded W26-T03 checks:

- `python -B -m unittest discover -s tests -p "test_wave26_gate.py"`:
  exit 0; 20 tests passed.
- `python -B scripts/check_wave26_gate.py`: exit 0.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`:
  exit 0; 97 tests passed.
- `python -B scripts/check_competition_matrix_gate.py`: exit 0.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  exit 0; 30 tests passed.
- `python -B scripts/check_docs_tree.py`: exit 0.
- `python -B scripts/check_archive_hygiene.py`: exit 0.

## W26-T04 Evidence

W26-T04 aligned documentation/status ledgers only.

Recorded W26-T04 checks:

- `python -B scripts/check_docs_tree.py`: exit 0; status `pass`.
- `python -B scripts/check_wave26_gate.py`: exit 0; status `pass`.
- `python -B scripts/check_competition_matrix_gate.py`: exit 0; status
  `pass`.

## W26-F01 Evidence

W26-F01 stabilizes aggregate-gate liveness by replacing the single opaque
release/offline `go test -p 1 -timeout 120s -count=1 ./...` Makefile step with
`python -B scripts/run_go_release_tests.py --go $(GO) --package-timeout 120`.
The helper enumerates Go packages deterministically, prints each package before
execution, uses release/offline environment variables, creates isolated
temporary `GOCACHE` and `APPDATA` paths outside the repository, and applies an
outer timeout to each package test process.

Recorded W26-F01 checks:

- `python -B -m unittest discover -s tests -p "test_wave26_gate.py"`:
  exit 0; 22 tests passed.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  exit 0; 30 tests passed.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`:
  exit 0; 97 tests passed.
- No-repo-cache `python -B -m py_compile` for all five Sentinel AML exploits
  and `scripts/run_go_release_tests.py`: exit 0.
- `python -B scripts/check_wave26_gate.py`: exit 0; status `pass`.
- `python -B scripts/run_go_release_tests.py --go go --package-timeout 120`:
  exit 0 after printing and testing each package from `go list ./...`.
- `python -B scripts/check_competition_matrix_gate.py`: exit 0; status
  `pass`.
- `python -B scripts/check_docs_tree.py`: exit 0; status `pass`.
- `python -B scripts/validate_forcad_config.py`: exit 0.
- `python -B scripts/check_archive_hygiene.py`: exit 0; status `pass`.
- `git apply --check --whitespace=error fixes/sentinel_aml/aml_dedup_preview.patch`:
  exit 0.
- `git apply --check --whitespace=error fixes/sentinel_aml/aml_audit_timeline.patch`:
  exit 0.
- `git apply --check --whitespace=error fixes/sentinel_aml/aml_related_graph.patch`:
  exit 0.
- Release/offline no-repo-cache `go vet ./...`: exit 0.
- A raw local `go vet ./...` without release/offline cache settings exited 1
  because the default Windows Go telemetry/cache paths were access denied; the
  release/offline no-repo-cache rerun above passed.
- An intermediate archive-hygiene run exited 1 after a raw local py-compile
  created `__pycache__` directories; the generated caches were removed, the
  no-repo-cache py-compile was rerun, and final archive hygiene passed.
- Local `timeout 300 make wave26-gate`: exit 1 before invoking project code
  because Windows `timeout.exe` does not execute commands.
- Local `make wave26-gate`: exit 1 because no make-compatible executable is
  installed on PATH.

Wave 26 remains implemented under review. The W26-F01 change is ready for exact
`timeout 300 make wave26-gate` re-review on a POSIX or make-equipped
orchestrator host.

## CTF Invariants

- Place 1 checker GET remains `GET /api/cases/{case_id}/notes`.
- Place 2 checker GET remains `GET /api/customers/{customer_id}/edd`.
- Strong CHECK/HAVOC remains release-blocking through checker tests in
  `wave26-gate`.
- Public attack data remains credential-free and raw-flag-free.
- Graph entity, related-case, and EDD-summary side views remain available for
  CHECK/HAVOC and business functionality.
- AML-4 and AML-5 reference fixes remain locked.

## Security Invariants

- Fixed AML-3 graph side-view output is public-only and contains no raw
  `EDDRecord.confidential_comment`.
- Owner EDD confidential comments remain visible only through owner EDD APIs.
- `CaseNote.body`, audit diffs, exports, network-room dossier internals,
  credentials, sessions, checker-private state, debug/admin paths, direct DB
  shortcuts, shell/subprocess primitives, broad serialization, endpoint-removal
  fixes, and cross-vulnerability chaining remain out of scope.

## Known Limitations

- Wave 26 is implemented under review, not accepted.
- Wave 27 remains locked until Wave 26 orchestrator acceptance.
- Local `timeout 300 make wave26-gate` evidence remains unavailable on this
  Windows host because Windows `timeout.exe` is not GNU `timeout` and no
  make-compatible executable is installed; W26-F01 records package-runner and
  component evidence for make-equipped re-review.
- Competition readiness remains incomplete until AML-4 and AML-5 fixes, the
  full regression matrix, packaging, and final validation pass.
