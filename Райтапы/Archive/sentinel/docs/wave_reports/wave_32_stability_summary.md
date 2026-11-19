# Wave 32 Stability Summary

## Summary

Wave 32 establishes Sentinel AML as a runtime/A-D stability candidate before
final packaging. The active review question is whether service, checker,
sploits, fixes, vulnerable profiles, runtime smoke, Go validation, ForcAD
layout, and documentation evidence are stable without release archive
generation.

Wave 32 does not issue a final release candidate, does not accept final
competition readiness, and does not promote any final package. Player/admin
packaging, code sanitization, player-facing leak cleanup, final manifests,
checksums, and final archive promotion are deferred to Wave 33+.

## Evidence Paths

- `docs/wave_reports/wave_32_checker_validation.md`
- `docs/wave_reports/wave_32_sploit_fix_matrix.md`
- `docs/wave_reports/wave_32_runtime_smoke.md`
- `docs/wave_reports/wave_32_stability_summary.md`
- `scripts/check_ad_stability_gate.py`
- `scripts/check_competition_matrix_gate.py`
- `scripts/run_vulnerable_profile_tests.py`
- `scripts/run_go_release_tests.py`
- `scripts/runtime_smoke.py`

## Commands Recorded

- `timeout 300 make ad-stability-gate` - exit 0; `ad-stability-gate: pass
  elapsed=72.350s`; outer elapsed about 84.048s in the target environment.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"` - exit 0,
  107 tests in 5.036s.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` -
  exit 0, 40 tests in 2.828s.
- `python -B -m unittest discover -s tests -p "test_runtime_smoke.py"` - exit 0,
  6 tests.
- `go test ./cmd/aml-api ./cmd/aml-worker ./internal/httpapi` - exit 0.
- `go test ./cmd/aml-worker` - exit 0.
- `go test ./internal/risk ./internal/alert ./internal/networkroom` - exit 0.
- `go test ./...` - exit 0.
- `python -B scripts/runtime_smoke.py` with
  `DATABASE_URL=postgres://sentinel:sentinel@localhost:55432/sentinel_aml_test?sslmode=disable`
  and `SENTINEL_AML_POSTGRES_PORT=55432` - exit 0;
  `runtime-smoke: pass elapsed=16.906s`.
- `python -B scripts/check_docs_tree.py` - exit 0 after Wave 32 ledger
  reconciliation.

## Stability Gate Boundary

`make ad-stability-gate` is archive-free. It includes checker unit/integration
tests, competition matrix validation, sploit syntax/import checks, fix patch
checks, vulnerable-profile runner, release-profile Go tests, Go vet/build,
docs-tree validation, and ForcAD config validation.

The gate excludes release archive creation, player bundle creation, final
manifest generation, and checksum generation. The historical `wave30-gate` and
W31 durable archive metadata remain review context only; they are not the active
runtime stability gate.

## Checker Evidence

Wave 32 checker evidence covers both active flag stores:

- place 1 stores `CaseNote.body` through owner case-note PUT/GET APIs;
- place 2 stores `EDDRecord.confidential_comment` through owner EDD PUT/GET
  APIs;
- CHECK/HAVOC covers basic, dedup, audit, graph, export, network-room, case
  notes, and EDD scenarios;
- public attack data remains locator-only and excludes credentials, sessions,
  raw flags, tokens, and private checker state.

Checker GET remains owner-view only and does not use vulnerable side views.

## Sploit/Fix Evidence

Wave 32 sploit/fix evidence covers AML-1 through AML-5 with these matrix cells:

- vulnerable profile builds;
- sploit syntax/import checks;
- expected business side-view path for each sploit;
- fix patch applies;
- fixed profile blocks the matched sploit;
- checker stays green after each fix;
- CHECK/HAVOC stays green after each fix.

All reference sploits remain business-logic clients using normal APIs and
public attack-locator data. No sploit depends on SQLi, shell execution,
debug/admin routes, or direct database access.

## Runtime Smoke Evidence

Wave 32 runtime smoke proves migrations, API health, worker restart safety, and
representative normal workflows against PostgreSQL. The target host required
the documented `55432` PostgreSQL port override because the default `54329`
host port was unavailable. Docker-unavailable skip mode returns exit 77 and
does not count as full acceptance.

## Ledger Reconciliation

Updated ledgers insert Wave 32 as runtime stability before packaging and defer
player/admin package promotion to Wave 33+. The updated files are:

- `docs/13_roadmap.md`
- `docs/waves.md`
- `docs/source_of_truth_map.md`
- `docs/definition_of_done.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`

## Invariants Preserved

- Two checker flag stores remain active.
- Five reference sploits and five reference fixes remain testable.
- Fix validation keeps checker PUT/GET and CHECK/HAVOC in scope.
- Checker uses normal APIs, not DB/debug/admin paths.
- Runtime smoke uses normal APIs and does not require checker-private
  credentials or direct DB writes.
- No status ledger implies readiness without checker, sploit, fix,
  vulnerable-profile, runtime, docs, and ForcAD evidence.
- Player-facing leak cleanup remains an open Wave 33+ risk.

## Risks and Deviations

- Full runtime smoke depends on Docker/PostgreSQL availability. The script can
  fail clearly or skip with exit 77 when explicitly requested, but skip mode is
  not acceptance evidence.
- The local target environment could not bind the default PostgreSQL host port
  `54329`; the documented override to `55432` produced passing runtime smoke
  evidence.
- Historical W30/W31 package artifacts are retained only as review context.
  They are not final package acceptance.

## Review State

Ready for orchestrator review: yes, for runtime/A-D stability only.
