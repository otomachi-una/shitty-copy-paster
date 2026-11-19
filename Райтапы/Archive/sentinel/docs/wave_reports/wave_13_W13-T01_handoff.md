# Wave 13 W13-T01 Handoff - CHECK/HAVOC Dispatcher and Result Model

## 1. Summary

Implemented the structured CHECK/HAVOC foundation for Sentinel AML. The checker
no longer relies on a shallow health-only CHECK: `check` and `havoc` route
through a named subcheck dispatcher that executes normal API workflows, keeps
Hackerdom-compatible exit classification, and redacts sensitive diagnostics.

## 2. Implementation Details

- Added `CheckSubcheck` as the named subcheck contract.
- Added `check_subchecks()` registry and `DEFAULT_CHECK_SUBCHECKS`.
- Added `run_check`, `run_havoc`, and `run_check_subchecks` dispatcher helpers.
- Added independent failure aggregation with `CheckFailedError`.
- Added `redact_sensitive` and `safe_error_message` for concise diagnostics.
- Preserved place 1 and place 2 PUT/GET owner-flow behavior.
- Kept deterministic checker fixture generation through shared HMAC/idempotency
  helpers.

## 3. Files Changed

- `checkers/sentinel_aml/checker.py`
- `checkers/sentinel_aml/checker_lib.py`
- `tests/test_checker_foundation.py`
- `tests/test_checker_check_workflow.py`
- `docs/08_checker_design.md`
- `docs/12_testing_strategy.md`
- `docs/wave_reports/wave_13_W13-T01_handoff.md`

## 4. Tests Added

- Named subcheck dispatch order.
- Unsupported subcheck fail-closed behavior.
- Independent failure aggregation.
- Sensitive-value redaction in subcheck and CLI errors.
- CHECK CLI dispatcher usage.
- HAVOC CLI dispatcher usage.
- Negative CHECK response handling.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_checker_foundation.py"`:
  pass.
- `python -B -m unittest discover -s tests -p "test_checker_check_workflow.py"`:
  pass.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`:
  pass.
- `python -B scripts\check_wave13_gate.py`: pass.

## 6. Documentation Updated

- `docs/08_checker_design.md` documents the Wave 13 CHECK/HAVOC framework,
  default subcheck set, failure classification, and redaction rules.
- `docs/12_testing_strategy.md` documents the Wave 13 dispatcher tests and gate
  expectations.

## 7. CTF Invariants Checked

- CHECK/HAVOC uses normal product HTTP APIs only.
- CHECK/HAVOC does not inspect the database.
- CHECK/HAVOC does not recover flags.
- PUT/GET semantics for both active flag stores remain owner-flow based.

## 8. Security Invariants Checked

- Flags, credentials, tokens, checker secrets, and private state are redacted
  from checker errors.
- CHECK output remains concise: success prints `OK`, failures print sanitized
  diagnostics to stderr.
- Unsupported subchecks and malformed responses fail closed.

## 9. Self-Review

The dispatcher foundation is intentionally small and explicit. It separates
framework behavior from business subcheck implementations, making later Wave 13
subchecks additive without changing the place 1/place 2 flag-store contract.

## 10. Risks / Open Questions

- Later Wave 13 tasks expand the default subcheck matrix beyond the initial
  W13-T01 foundation; those additions are compatible with this dispatcher.
- Full all-test discovery may still include historical wave-specific tests whose
  older expectations conflict with later accepted wave state.

## 11. Ready for Orchestrator Review

Yes.
