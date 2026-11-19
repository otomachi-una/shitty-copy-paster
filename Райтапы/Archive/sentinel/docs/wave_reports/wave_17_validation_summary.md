# Wave 17 Validation Summary

## Scope Validated

Wave 17 introduces AML-4 only as a controlled tagged vulnerable profile:
`aml4_vulnerable`. The intended vulnerable process is authenticated
`POST /api/disputes/{dispute_id}/export`, where a requester-owned dispute/root
case may produce an export bundle containing linked duplicate-case private
analyst notes in `linked_private_notes[]`.

The default build remains the secure recursive export baseline. AML-4 reference
exploit and reference fix artifacts remain locked. AML-5 remains future-only.

Status after W17-F02 reconciliation: Wave 17 is accepted/complete based on the
W17-F01 deterministic wrapper evidence. Wave 18 is planned and unlocked as the
next vulnerability wave, but AML-5 implementation has not started in this
fix task. AML-4 exploit and fix waves remain locked to the planned sequence.

## Command Evidence

W17-T01 implementation evidence:

```sh
go test ./internal/exporting ./internal/httpapi
go test -tags aml4_vulnerable ./internal/exporting ./internal/httpapi
go test ./...
go test -tags aml4_vulnerable ./...
go vet ./...
```

Results: all passed.

W17-T02 gate evidence:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave17_gate.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
go test ./...
go test -tags aml4_vulnerable ./...
go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/check_wave17_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/validate_forcad_config.py
python -B scripts/check_archive_hygiene.py
```

Results: all passed. Checker unittest discovery returned after 97 tests.

Before W17-F01, `make wave17-gate` could not be executed on the local Windows
PowerShell host because `make` is not installed, and the orchestrator later
observed the wrapper timing out at the default package-parallel tagged sweep.
That blocker is superseded by the W17-F01 deterministic wrapper evidence below.

W17-T03 documentation evidence:

```sh
python -B scripts/check_docs_tree.py
python -B scripts/check_wave17_gate.py
python -B scripts/check_competition_matrix_gate.py
```

Results: all passed.

W17-F01 deterministic wrapper evidence:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave17_gate.py"
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -p 1 -tags aml4_vulnerable ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/check_wave17_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/validate_forcad_config.py
timeout 300 make wave17-gate
```

Results: all passed with exit 0. The local Windows PowerShell host still lacks
native `make` and uses Windows `timeout.exe`, so literal wrapper execution was
performed through WSL with POSIX `/usr/bin/timeout` and `/usr/bin/make`, plus
temporary PATH shims for the expected `python` command and compatible Go
toolchain. The Makefile target now runs the AML-4 vulnerable all-package sweep
as `go test -p 1 -tags aml4_vulnerable ./...`.

## CTF Invariants

- Checker PUT/GET remains owner-view and HTTP-only for both active places.
- Public attack data remains locator-only and credential-free.
- AML-4 is available only through `aml4_vulnerable`.
- AML-4 exploit/fix artifacts remain absent and locked.
- AML-5 remains locked until Wave 18.
- The competition matrix marks AML-1 through AML-4 vulnerable-checker cells as
  concrete and leaves exploit/fix cells pending.

## Security Invariants

- Default export build remains recursively redacted.
- Tagged AML-4 leak is bounded to linked duplicate-case private note `body`
  values in dispute export bundles.
- Root private notes, `EDDRecord.confidential_comment`, EDD narrative fields,
  raw audit diffs, graph data, network-room dossiers, credentials, sessions,
  checker-private state, public attack data, and raw database rows remain
  forbidden outside their intended owner paths.
- No debug/admin runtime toggles or direct DB checker paths were introduced.

## Known Gaps

- No Wave 17 closure blocker remains after W17-F01 wrapper evidence and W17-F02
  status reconciliation.
- Wave 22 AML-4 reference exploit and Wave 27 AML-4 reference fix remain
  locked until their planned sequence.

## Ready For Orchestrator Review

yes
