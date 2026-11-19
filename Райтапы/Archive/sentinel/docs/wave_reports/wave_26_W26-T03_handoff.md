# Wave 26 W26-T03 Handoff

## 1. Summary

Strengthened AML-3 exploit-blocked and anti-coarse-fix evidence. The tests now prove that the exploit parser succeeds on vulnerable fixture output containing `confidential_comment`, fails safely on fixed graph summary output, and that fixed graph fixtures preserve public graph evidence plus owner-only EDD access. The owner EDD API remains the only route for the private EDD comment.

## 2. Implementation Details

- Extended `tests/test_wave26_gate.py` with embedded AML-3 fixed graph fixtures.
- Added direct exploit parser coverage for vulnerable and fixed graph EDD-summary payloads.
- Added fixed-service evidence for `/api/graph/entities/{entity_hint}`, `/related-cases`, `/edd-summaries`, and owner-only `/api/customers/{customer_id}/edd`.
- Strengthened `scripts/check_wave26_gate.py` to reject renamed sensitive EDD comment fields, hash/raw-diff leakage, graph endpoint deletion, graph repository deletion, graph proof-test deletion, direct DB shortcuts, shell helpers, and debug/admin routes.

## 3. Files Changed

- `scripts/check_wave26_gate.py`
- `tests/test_wave26_gate.py`
- `docs/wave_reports/wave_26_W26-T03_handoff.md`

## 4. Tests Added

- Exploit parser succeeds on vulnerable fixture output containing `confidential_comment`.
- Exploit parser fails safely on fixed graph summary output without raw private fields.
- Fixed graph fixture preserves public graph/entity/related-case/EDD-summary evidence.
- Owner EDD API remains the only route for the private EDD comment.
- Gate tests reject `/edd-summaries`, `/related-cases`, graph repository, and graph proof-test deletion.
- Gate tests reject renamed confidential-comment fields, hashes, and raw audit diffs.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_wave26_gate.py"` - exit 0, 20 tests passed.
- `python -B scripts/check_wave26_gate.py` - exit 0.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"` - exit 0, 97 tests passed.
- `python -B scripts/check_competition_matrix_gate.py` - exit 0.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` - exit 0, 30 tests passed.
- `python -B scripts/check_docs_tree.py` - exit 0.
- `python -B scripts/check_archive_hygiene.py` - exit 0.

## 6. Documentation Updated

- Created this W26-T03 handoff.

## 7. CTF Invariants Checked

- Exploit is blocked only against fixed output; vulnerable-profile evidence remains intact.
- CHECK/HAVOC retains graph functionality to test through public graph endpoints and bounded owner EDD access.
- AML-4 and AML-5 fixes remain absent.

## 8. Security Invariants Checked

- Fixed graph side views must not leak EDD comments, case notes, audit diffs, export internals, network dossier internals, credentials, or session tokens.
- Owner EDD remains owner-only through `/api/customers/{customer_id}/edd`.
- Graph visibility remains separate from EDD confidential visibility.

## 9. Self-Review

- No exploit script or product Go source was edited.
- Fixtures are embedded in `tests/test_wave26_gate.py`.
- The gate remains deterministic and static, following the prior Wave 24-26 pattern.

## 10. Risks / Open Questions

- Runtime application of the AML-3 patch remains covered by W26-T01; this task strengthens parser and anti-coarse evidence in the gate tests.
- The anti-coarse checks are static and marker-based, so future patch refactors may need corresponding gate-marker updates if they preserve behavior through different local names.

## 11. Ready for Orchestrator Review

Yes.
