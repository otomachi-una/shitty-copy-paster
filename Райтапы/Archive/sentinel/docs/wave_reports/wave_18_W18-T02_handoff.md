# Wave 18 W18-T02 Handoff

## 1. Summary

Added the Wave 18 closure gate and competition-matrix evidence for the AML-5
vulnerable-checker cell. AML-5 is now concrete only for the tagged
vulnerable-checker profile introduced by W18-T01; exploit-success, fixed
checker, exploit-blocked, and anti-coarse-fix cells remain pending.

Wave 18 remains ready for orchestrator review and is not marked accepted by
this handoff.

## 2. Implementation Details

- Added `make wave18-gate` with deterministic checker discovery, Wave 18 gate
  tests, competition-matrix tests, default Go tests, serialized AML-5 tagged Go
  tests, Go vet, docs tree validation, Wave 18 gate validation, competition
  matrix validation, and ForcAD config validation.
- Extended `scripts/check_wave18_gate.py` to validate that `wave18-gate` runs
  the full required command set and uses `go test -p 1 -tags aml5_vulnerable
  ./...` for the tagged vulnerable sweep.
- Updated the competition matrix gate so AML-1 through AML-5 vulnerable-checker
  cells are concrete, while all exploit/fix cells remain pending.
- Replaced the prior AML-5 future-lock check with an unsequenced AML marker
  guard that rejects AML-6-style activation while allowing W18 AML-5 evidence.
- Kept exploit/fix artifact rejection active for AML-5 and preserved the
  debug/admin toggle guard.

## 3. Files Changed

- `Makefile`
- `scripts/check_wave18_gate.py`
- `tests/test_wave18_gate.py`
- `scripts/check_competition_matrix_gate.py`
- `tests/test_competition_matrix_gate.py`
- `docs/wave_reports/wave_18_W18-T02_handoff.md`

## 4. Tests Added

- Wave 18 gate tests requiring the `wave18-gate` Makefile target and serialized
  AML-5 tagged sweep.
- Competition matrix tests requiring AML-5 concrete checker artifacts.
- Competition matrix tests rejecting early AML-5 sploit/fix files.
- Competition matrix tests rejecting unsequenced AML-6 activation markers.

## 5. Tests Run

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
```

Exit code: 0. Ran 97 tests.

```sh
python -B -m unittest discover -s tests -p "test_wave18_gate.py"
```

Exit code: 0. Ran 7 tests.

```sh
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
```

Exit code: 0. Ran 16 tests.

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
```

Exit code: 0.

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -p 1 -tags aml5_vulnerable ./...
```

Exit code: 0. This is the deterministic tagged-test strategy established by
the Wave 17 gate fix.

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
```

Exit code: 0.

```sh
python -B scripts/check_docs_tree.py
```

Exit code: 0.

```sh
python -B scripts/check_wave18_gate.py
```

Exit code: 0.

```sh
python -B scripts/check_competition_matrix_gate.py
```

Exit code: 0.

```sh
python -B scripts/validate_forcad_config.py
```

Exit code: 0.

```sh
timeout 300 make wave18-gate
```

Exit code: 0. Executed through WSL GNU `timeout`/`make` on this Windows host;
the wrapper completed the checker, Python, Go, docs, matrix, and ForcAD steps.

## 6. Documentation Updated

Added this W18-T02 handoff report with the gate, matrix, invariant, and
self-review evidence for orchestrator review.

## 7. CTF Invariants Checked

- Both checker places remain active; checker code was not changed.
- CHECK/HAVOC behavior remains untouched.
- Public attack data remains locator-only; public attack artifacts were not
  changed.
- AML-5 exploit/fix cells remain pending.
- Reference sploit and fix directories still reject AML-5 artifacts.

## 8. Security Invariants Checked

- No runtime vulnerability switches were added.
- No broad source-case, EDD, or audit-row serialization was added in this task.
- No credential, session, checker-private, debug/admin, or direct DB checker
  path was added.

## 9. Self-Review

The gate update is intentionally scoped to validation and release evidence.
Product semantics, checker behavior, public attack data, ForcAD config,
reference sploits, reference fixes, and AML-1 through AML-4 profile behavior
were left untouched.

## 10. Risks / Open Questions

- Wave 18 still requires orchestrator acceptance after `timeout 300 make
  wave18-gate` evidence is reviewed.
- Future AML-5 exploit and fix waves remain sequenced and locked until their
  planned tasks.

## 11. Ready for Orchestrator Review

yes
