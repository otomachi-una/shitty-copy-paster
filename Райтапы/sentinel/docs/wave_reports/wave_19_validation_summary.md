# Wave 19 Validation Summary - AML-1 Reference Exploit

## Status

Wave 19 is implemented under review. It is not marked accepted. The only Wave
19 reference exploit is `sploits/sentinel_aml/aml_dedup_preview.py`, which
targets the accepted AML-1 `aml1_vulnerable` dedup merge-preview leak.

Wave 20 remains queued/locked until the orchestrator accepts Wave 19. Wave 24
and all other reference-fix waves remain locked until their corresponding
exploit evidence is accepted and the fix wave opens in sequence.

## Scope Evidence

- Exactly one exploit script is present under `sploits/sentinel_aml/`:
  `aml_dedup_preview.py`.
- `fixes/sentinel_aml/` remains README-only.
- AML-2 through AML-5 exploit scripts remain absent:
  `aml_audit_timeline.py`, `aml_related_graph.py`,
  `aml_export_redaction.py`, and `aml_network_room.py`.
- No checker code, product code, service configuration, public attack-data
  schema, or reference-fix artifact is part of Wave 19.

## Exploit Evidence

The AML-1 reference exploit:

- accepts host, port, and public attack-info JSON or path;
- validates public place 1 `CaseNote.body` attack data with `case_id` and
  `dedup_hint`;
- registers and logs in as an attacker account;
- creates attacker-owned customer/account/transaction/alert/case workflow
  state using the victim `dedup_hint`;
- requests the normal duplicate candidate and merge-preview side views;
- extracts a flag-like token only from leaked
  `candidate.private_notes[].body`;
- exits non-zero with concise stderr when secure/default behavior omits
  `private_notes`.

## Matrix Interpretation

The competition matrix is aligned as follows:

- AML-1 vulnerable checker gate: concrete.
- AML-1 exploit-success gate: concrete under Wave 19 review.
- AML-1 fixed checker, exploit-blocked, and anti-coarse-fix gates: pending.
- AML-2 through AML-5 vulnerable checker gates: concrete from their accepted
  vulnerable-profile waves.
- AML-2 through AML-5 exploit-success gates: pending/locked.
- AML-2 through AML-5 fixed checker, exploit-blocked, and anti-coarse-fix
  gates: pending/locked.

## Validation Commands

Recorded Wave 19 validation evidence:

- `python -B -m unittest discover -s tests -p "test_checker_*.py"`: passed.
- `python -B -m unittest discover -s tests -p "test_wave19_gate.py"`:
  passed.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  passed.
- `python -B scripts/check_wave19_gate.py`: passed.
- `python -B scripts/check_competition_matrix_gate.py`: passed.
- `python -B scripts/check_docs_tree.py`: passed.
- `python -B scripts/validate_forcad_config.py`: passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...`:
  passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...`:
  passed.
- `timeout 300 make wave19-gate`: passed on the local review host through WSL
  with temporary `/tmp` command shims because native Windows `make` was absent.

## Invariants

- Both active checker flag stores remain unchanged:
  `CaseNote.body` and `EDDRecord.confidential_comment`.
- CHECK/HAVOC remains unchanged and strong.
- Public attack data remains credential-free and does not gain new fields.
- The exploit is not a checker dependency.
- No hidden debug/admin route, direct DB path, shell behavior, leaked
  credential path, or checker-private-state path is normalized.
- The default secure build remains safe against the AML-1 merge-preview leak.

## Remaining Risks

- Wave 19 still needs orchestrator acceptance before Wave 20 can open.
- Wave 24 remains locked until accepted AML-1 exploit evidence is available
  and the fix wave opens.
- Future exploit waves must continue to add exactly one exploit each and avoid
  generic exploit-framework behavior.

## Next Wave Candidate

After Wave 19 acceptance, the next queued candidate is Wave 20:
`sploits/sentinel_aml/aml_audit_timeline.py`. Until acceptance, Wave 20 remains
locked.
