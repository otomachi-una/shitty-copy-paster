# Wave 13 Review

## Status

Status: needs fixes.

## Review Evidence

The orchestrator observed `make wave13-gate` start
`python -B -m unittest discover -s tests -p "test_checker_*.py"` and produce
successful test progress without terminating before timeout. W13-F01 identified
the test-resource lifecycle cause and fixed fake checker HTTP servers so full
checker unittest discovery exits cleanly.

Agent-side W13-F01 evidence:

- `python -B -m unittest discover -s tests -p "test_checker_resource_lifecycle.py"` passed with 2 tests.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"` passed with 97 tests and exited cleanly.
- `python -B -m unittest discover -s tests -p "test_wave13_gate.py"` passed with 9 tests.
- `python -B scripts/check_docs_tree.py` passed.
- `python -B scripts/check_wave13_gate.py` passed.
- `python -B scripts/validate_forcad_config.py` passed.
- `python -B scripts/check_competition_matrix_gate.py` passed.
- Go test/vet passed with vendor mode, telemetry disabled, and workspace-local
  Go cache/profile paths.

The local Windows host used by the agent does not have `make`,
`mingw32-make`, or `nmake` installed, so the literal `make wave13-gate` command
could not be executed there. The Makefile target remains wired to the same
component gate commands.

## Close Conditions

Wave 13 can move from `needs fixes` to `complete` only after the orchestrator
reruns `make wave13-gate` and records successful process exit. Wave 14 remains
blocked until Wave 13 acceptance.

Reconciliation note, 2026-09-01: W15-F01 fixed the analogous Wave 15 checker
discovery liveness symptom in the active test helpers, but that later evidence
does not rewrite this Wave 13 review outcome. Wave 13 remains `needs fixes`
until its own `make wave13-gate` re-review is accepted.

## Invariants

- Checker PUT/GET semantics for both places remain unchanged.
- CHECK/HAVOC uses normal product HTTP APIs only.
- No direct database checker access, hidden debug/admin endpoint, planned
  vulnerability, reference exploit, or reference fix is active.
- Public attack data remains locator-only and excludes credentials, tokens,
  private state, and raw flags.
