# Wave 21 Validation Summary

## Scope Validated

Wave 21 implements the AML-3 reference exploit under review. The exploit is
`sploits/sentinel_aml/aml_related_graph.py`; it is the only new exploit after
the accepted Wave 19 AML-1 exploit `aml_dedup_preview.py` and the accepted Wave
20 AML-2 exploit `aml_audit_timeline.py`.

Wave 21 is not accepted by this summary. Orchestrator review remains the only
authority that can accept Wave 21 and unlock Wave 22. Wave 22, Wave 23, and
W24-W28 reference fix waves remain locked.

The current branch evidence shows:

- AML-1 exploit-success remains concrete from Wave 19.
- AML-2 exploit-success remains concrete from Wave 20.
- AML-3 exploit-success is concrete under Wave 21 review.
- AML-4 and AML-5 exploit-success cells remain pending/locked.
- AML-1 through AML-5 fix cells remain pending/locked.
- `fixes/sentinel_aml/` remains README-only.

## Exploit Evidence

The AML-3 exploit:

- accepts host, port, and public attack-info JSON or a JSON file;
- validates `sentinel_aml` place 2 `EDDRecord` attack data with public
  `customer_id`, `entity_hint`, and locator metadata;
- rejects credential-like, checker-private, confidential, and flag-like public
  attack data;
- registers and logs in as an attacker with deterministic non-secret data
  derived from public attack data;
- creates only attacker-owned graph participation with the victim
  `entity_hint`;
- requests only the related graph side view
  `GET /api/graph/entities/{entity_hint}/edd-summaries`;
- extracts a flag-like token only from leaked
  `summaries[].confidential_comment`;
- exits non-zero without stdout flag material when the graph response is secure
  or redacted.

The exploit does not call the checker owner GET path
`GET /api/customers/{customer_id}/edd`; checker GET for place 2 remains the
owner EDD path and is not replaced by the graph side view.

## Matrix Interpretation

`scripts/check_competition_matrix_gate.py` validates the current Wave 21 matrix
state:

- AML-1 vulnerable checker gate: concrete.
- AML-1 exploit-success gate: concrete.
- AML-2 vulnerable checker gate: concrete.
- AML-2 exploit-success gate: concrete.
- AML-3 vulnerable checker gate: concrete.
- AML-3 exploit-success gate: concrete under review.
- AML-4 and AML-5 vulnerable checker gates: concrete from their accepted
  vulnerable-profile waves.
- AML-4 and AML-5 exploit-success gates: pending/locked.
- AML-1 through AML-5 fixed checker, exploit-blocked, and anti-coarse-fix
  gates: pending/locked.

## Commands Recorded

W21-T01 implementation evidence:

| Command | Result |
| --- | --- |
| `python -B -m py_compile sploits\sentinel_aml\aml_related_graph.py` | exit 0 |
| `python -B -m unittest discover -s tests -p "test_wave21_gate.py"` | exit 0; 7 tests passed at T01, then 14 tests after T02 gate expansion |
| `python -B scripts\check_docs_tree.py` | exit 0; pass |
| `python -B scripts\check_archive_hygiene.py` | exit 0; pass after generated local bytecode was removed |

W21-T02 validation evidence:

| Command | Result |
| --- | --- |
| `python -B -m unittest discover -s tests -p "test_checker_*.py"` | exit 0; 97 tests passed |
| `python -B -m unittest discover -s tests -p "test_wave21_gate.py"` | exit 0; 14 tests passed |
| `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` | exit 0; 23 tests passed |
| `python -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py` | exit 0 |
| `python -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py` | exit 0 |
| `python -B -m py_compile sploits/sentinel_aml/aml_related_graph.py` | exit 0 |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...` | exit 0 through PowerShell-equivalent environment assignment with cache under `$env:TEMP` |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...` | exit 0 through PowerShell-equivalent environment assignment with cache under `$env:TEMP` |
| `python -B scripts/check_wave21_gate.py` | exit 0; pass |
| `python -B scripts/check_competition_matrix_gate.py` | exit 0; pass |
| `python -B scripts/check_docs_tree.py` | exit 0; pass |
| `python -B scripts/validate_forcad_config.py` | exit 0; `config.yml ForcAD shape is valid` |
| `python -B scripts/check_archive_hygiene.py` | exit 0; pass |
| `timeout 300 make wave21-gate` | not proven in the Windows PowerShell session because `timeout` resolved to Windows `timeout.exe` and `make` was unavailable in PATH |

W21-T03 documentation/status validation:

| Command | Result |
| --- | --- |
| `python -B scripts/check_docs_tree.py` | exit 0; pass |
| `python -B scripts/check_wave21_gate.py` | exit 0; pass |
| `python -B scripts/check_competition_matrix_gate.py` | exit 0; pass |
| `python -B scripts/check_archive_hygiene.py` | exit 0; pass |

## CTF Invariants

- `CaseNote.body` and `EDDRecord.confidential_comment` remain the only checker
  flag stores.
- Checker place 1 GET still reads owner case notes through
  `GET /api/cases/{case_id}/notes`.
- Checker place 2 GET still reads owner EDD records through
  `GET /api/customers/{customer_id}/edd`.
- CHECK/HAVOC remains covered by checker tests and the aggregate gate target.
- Public attack data remains credential-free and locator-only.
- Exploits remain outside checker code.
- `fixes/sentinel_aml/` remains README-only.

## Security Invariants

- AML-3 exploit evidence is bounded to related graph EDD summary exposure.
- No direct database access, SQL injection, shell execution, debug/admin route,
  credential leak, session theft, generic exploit framework, owner EDD API
  abuse, audit timeline path, export path, network-room path, or
  cross-vulnerability chain is documented as acceptable.
- The default secure graph build remains metadata-only.
- Reference fixes remain locked under `fixes/sentinel_aml/`.

## Known Gaps

- Wave 21 is implemented under review and still awaits orchestrator acceptance.
- Exact `timeout 300 make wave21-gate` evidence still needs a make-capable
  POSIX/coreutils review environment.
- Wave 22 remains locked until Wave 21 acceptance.
- Wave 26 remains locked until accepted AML-3 exploit evidence and the fix wave
  open in sequence.

## Status

Wave 21 is implemented under review. AML-3 exploit-success evidence is
concrete under review. Wave 22, Wave 23, and all reference fix waves remain
locked.
