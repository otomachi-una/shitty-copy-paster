# Wave 20 Validation Summary

## Scope Validated

Wave 20 implements the accepted AML-2 reference exploit. W20-F01 fixed the
gate-liveness and archive-hygiene review findings, W20-F02 reconciled the
status ledgers, and re-review evidence records `timeout 300 make wave20-gate`
exiting 0. The exploit is `sploits/sentinel_aml/aml_audit_timeline.py`; it is
the only new exploit after the accepted Wave 19 AML-1 exploit
`sploits/sentinel_aml/aml_dedup_preview.py`.

Wave 20 is marked accepted by this reconciliation evidence. Wave 21 is now the
next queued exploit wave, but it is not started by this summary. Wave 25, the
AML-2 fix wave, remains locked until accepted AML-2 exploit evidence exists and
the fix wave opens in sequence.

The current branch evidence shows:

- AML-1 exploit-success remains concrete from Wave 19.
- AML-2 exploit-success is concrete after Wave 20 acceptance.
- AML-3 through AML-5 exploit-success cells remain pending/locked.
- AML-1 through AML-5 fix cells remain pending/locked.
- `fixes/sentinel_aml/` remains README-only.

## Exploit Evidence

The AML-2 exploit:

- accepts host, port, and public attack-info JSON or a JSON file;
- validates `sentinel_aml` place 1 `CaseNote.body` attack data with public
  `case_id` and locator metadata;
- registers and logs in as an attacker with deterministic non-secret data
  derived from public attack data;
- requests only the normal audit side view
  `GET /api/cases/{case_id}/timeline`;
- extracts a flag-like token only from `case_note` audit changes where
  `field` is `case_note.body` or `body` and `redacted` is explicitly `false`,
  including equivalent audit `diff_json` material;
- exits non-zero without stdout flag material when the timeline is secure or
  redacted.

The exploit does not call the checker owner GET path
`GET /api/cases/{case_id}/notes`; checker GET for place 1 remains the owner
note path and is not replaced by the audit side view.

## Matrix Interpretation

`scripts/check_competition_matrix_gate.py` now validates the current Wave 20
matrix state:

- AML-1 vulnerable checker gate: concrete.
- AML-1 exploit-success gate: concrete.
- AML-2 vulnerable checker gate: concrete.
- AML-2 exploit-success gate: concrete after Wave 20 acceptance.
- AML-3 through AML-5 vulnerable checker gates: concrete from their accepted
  vulnerable-profile waves.
- AML-3 through AML-5 exploit-success gates: pending/locked.
- AML-1 through AML-5 fixed checker, exploit-blocked, and anti-coarse-fix
  gates: pending/locked.

## Commands Run

W20-T02 recorded full gate evidence:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave20_gate.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
timeout 300 make wave20-gate
```

Results:

| Command | Result |
| --- | --- |
| `python -B -m unittest discover -s tests -p "test_checker_*.py"` | exit 0; pass; 97 tests |
| `python -B -m unittest discover -s tests -p "test_wave20_gate.py"` | exit 0; pass; 12 tests |
| `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` | exit 0; pass; 21 tests |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...` | exit 0 after rerun outside sandbox because the Windows Go cache was denied under sandboxed execution |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...` | exit 0 after rerun outside sandbox for the same Go cache issue |
| `timeout 300 make wave20-gate` | exit 0; pass via WSL `/usr/bin/make` with temporary `/tmp/w20gate-bin` command shims on this Windows host |

W20-T03 documentation/status validation:

```sh
python -B scripts/check_docs_tree.py
python -B scripts/check_wave20_gate.py
python -B scripts/check_competition_matrix_gate.py
```

Results:

| Command | Result |
| --- | --- |
| `python -B scripts/check_docs_tree.py` | exit 0; pass |
| `python -B scripts/check_wave20_gate.py` | exit 0; pass |
| `python -B scripts/check_competition_matrix_gate.py` | exit 0; pass |

## W20-F01 Gate Liveness And Archive Hygiene

W20-F01 addresses orchestrator review feedback that the submitted archive
contained generated Python bytecode under `sploits/sentinel_aml/__pycache__/`
and that the exact aggregate wrapper did not terminate reproducibly.

Fixed evidence:

- generated `__pycache__/`, `.pyc`, and `.pyo` artifacts are removed from the
  repository snapshot;
- `.gitignore` explicitly covers Python bytecode, local Go/application caches,
  IDE metadata, archive files, and local scratch directories;
- `wave20-gate` redirects exploit `py_compile` bytecode through
  `PYTHONPYCACHEPREFIX` outside the repository snapshot;
- `wave20-gate` runs `python -B scripts/check_archive_hygiene.py` as its final
  closure command after all commands that may generate bytecode;
- `scripts/check_wave20_gate.py` requires archive hygiene wiring and W20-F01
  handoff evidence.

W20-F01 validation results:

| Command | Result |
| --- | --- |
| `python -B scripts/check_archive_hygiene.py` | exit 0; pass |
| `python -B -m unittest discover -s tests -p "test_archive_hygiene.py"` | exit 0; pass; 8 tests |
| `python -B -m unittest discover -s tests -p "test_checker_*.py"` | exit 0; pass; 97 tests |
| `python -B -m unittest discover -s tests -p "test_wave20_gate.py"` | exit 0; pass; 13 tests |
| `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` | exit 0; pass; 21 tests |
| `python -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py` | exit 0; pass |
| `python -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py` | exit 0; pass |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...` | exit 0; pass after rerun outside the restricted sandbox because the Windows Go build cache was denied in sandboxed execution |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...` | exit 0; pass after rerun outside the restricted sandbox for the same Go cache condition |
| `timeout 300 make wave20-gate` | exit 0; pass in 17.5 seconds via WSL `/usr/bin/make` without temporary command shims |
| `python -B scripts/check_archive_hygiene.py` after aggregate gate | exit 0; pass |

The standalone `py_compile` component checks can create interpreter bytecode in
the local working tree; those artifacts were removed. The official aggregate
gate now redirects compile bytecode outside the repository and validates archive
hygiene after every other closure command.

## W20-F02 Status-Ledger Reconciliation

W20-F02 reconciles the documentation ledgers after W20-F01. The fixed evidence
was recorded without advancing Wave 20 to accepted status inside that agent
handoff. The post-acceptance status wording is:

- Wave 20 is complete after W20-F01/W20-F02 reconciliation and exit-0
  `timeout 300 make wave20-gate` re-review evidence.
- Wave 21 is queued as the next allowed exploit wave, but not started by this
  Wave 20 acceptance reconciliation.
- Wave 25 and all other reference fix waves remain locked until accepted
  exploit evidence and scheduled fix-wave opening.
- Matrix interpretation remains AML-1 and AML-2 exploit-success concrete,
  AML-3 through AML-5 exploit-success pending, and all fixes pending.

## Wave 20 Acceptance Reconciliation

The acceptance procedure reran the official aggregate gate:

| Command | Result |
| --- | --- |
| `timeout 300 make wave20-gate` | exit 0; pass in 19.0 seconds via WSL `/usr/bin/make` without temporary command shims |
| `python -B scripts/check_docs_tree.py` | exit 0; pass |
| `python -B scripts/check_wave20_gate.py` | exit 0; pass |
| `python -B scripts/check_competition_matrix_gate.py` | exit 0; pass |
| `python -B scripts/check_archive_hygiene.py` | exit 0; pass |

This reconciles Wave 20 as accepted in the status ledgers. It unlocks only the
queued Wave 21 AML-3 reference exploit scope. AML-4/AML-5 exploits and W24-W28
reference fixes remain locked.

## CTF Invariants

- `CaseNote.body` and `EDDRecord.confidential_comment` remain the only checker
  flag stores.
- Checker place 1 GET still reads owner case notes through
  `GET /api/cases/{case_id}/notes`.
- Checker place 2 GET still reads owner EDD records through
  `GET /api/customers/{customer_id}/edd`.
- CHECK/HAVOC remains covered by checker tests and `wave20-gate`.
- Public attack data remains credential-free and locator-only.
- Exploits remain outside checker code.

## Security Invariants

- AML-2 exploit evidence is bounded to audit timeline/diff exposure.
- No direct database access, SQL injection, shell execution, debug/admin route,
  credential leak, session theft, generic exploit framework, graph/export/
  network-room path, or EDD side-view behavior is documented as acceptable.
- The default secure build remains expected to redact sensitive audit changes.
- Reference fixes remain locked under `fixes/sentinel_aml/`.

## Known Gaps

- Wave 21 is queued but not started.
- Wave 25 remains locked until accepted AML-2 exploit evidence and the fix wave
  opens in sequence.

## Status

Wave 20 is complete after W20-F01/W20-F02 reconciliation and exit-0
`timeout 300 make wave20-gate` re-review evidence. Wave 21 is the next queued
exploit wave; Wave 22 and all fix waves remain locked.
