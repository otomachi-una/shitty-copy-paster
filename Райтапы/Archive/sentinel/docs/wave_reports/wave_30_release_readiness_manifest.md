# Wave 30 Release Readiness Manifest

## Status

Wave 30 is implemented under review. Wave 29 is accepted as the prerequisite
for this manifest after full matrix/regression evidence, W29-F01 aggregate gate
liveness evidence, and W29-F02 status reconciliation. This manifest freezes the
authoritative requirements for final competition packaging, but it does not by
itself claim final competition readiness.

## Frozen Source-of-Truth Map

The following documents own release requirements:

- Project purpose and runtime shape: `docs/00_project_overview.md`.
- ForcAD and CTF contract: `docs/01_ctf_contract.md`.
- Domain concepts: `docs/02_domain_model.md`.
- API contract: `docs/03_api_contract.md`.
- Database model: `docs/04_database_model.md`.
- Authentication and authorization: `docs/05_authentication_authorization.md`.
- Visibility, projections, and side-view boundaries:
  `docs/06_visibility_and_projections.md`.
- Flag stores: `docs/07_flag_stores.md`.
- Checker contract and PUT/GET/CHECK/HAVOC behavior:
  `docs/08_checker_design.md`.
- Vulnerability behavior, exploit/fix sequencing, and protected-field
  boundaries: `docs/09_vulnerability_matrix.md`.
- Workers and async flows: `docs/10_workers_and_async_flows.md`.
- Deployment: `docs/11_deployment.md`.
- Tests and release gates: `docs/12_testing_strategy.md`.
- Status ledger: `docs/13_roadmap.md`.
- Execution history: `docs/14_agent_execution_log.md`.
- Risks: `docs/15_risk_register.md`.
- Completion criteria: `docs/definition_of_done.md`.
- Wave decomposition: `docs/waves.md`.
- Release-readiness freeze and final evidence manifest:
  `docs/wave_reports/wave_30_release_readiness_manifest.md`.

No source-of-truth requirement change is allowed after this freeze without a
new ADR. The ADR must name the authoritative document changed, the affected CTF
or security invariant, the validation commands to rerun, and any packaging
impact.

## Historical Artifacts

Wave handoffs, validation summaries, prompt pools under `docs/agent_packets/`,
and archived foreign material are historical or reference-only review artifacts.
They do not override the frozen source-of-truth documents above unless a new ADR
explicitly promotes a requirement.

Root-level prompt pools remain non-canonical. Foreign legacy material, if
retained, must stay under `docs/archive/foreign_voltax/`.

## Required Release Evidence

Final competition packaging must record exact command evidence for:

- `timeout 300 make wave30-gate` exiting 0 on the release review host as the
  Final release gate.
- `timeout 300 make wave29-gate` exiting 0 on the release review host.
- `python -B scripts/check_competition_matrix_gate.py` exiting 0.
- `python -B scripts/check_wave29_gate.py` exiting 0.
- `python -B scripts/check_wave29_regression.py` exiting 0.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"` exiting 0.
- `python -B scripts/check_docs_tree.py` exiting 0.
- `python -B scripts/validate_forcad_config.py` exiting 0.
- `python -B scripts/check_archive_hygiene.py` exiting 0 after any packaging
  or aggregate gate run.
- Release/offline Go tests and vet under `GOTOOLCHAIN=local`,
  `GOFLAGS=-mod=vendor`, and `GOTELEMETRY=off`.
- Compilation of exactly five reference sploits with repository bytecode
  disabled.
- Clean `git apply --check --whitespace=error` evidence for exactly five
  reference fix patches.

The final aggregate gate may use shared out-of-repository release caches for
one gate invocation to stay within the 300-second review bound. Such caches
must remain outside the repository and must not change evidence coverage:
checker tests, matrix tests, all five sploit compiles, all five patch apply
checks, AML-1 through AML-5 vulnerable-profile tests, untagged release/offline
Go tests, Go vet, docs-tree, ForcAD, archive hygiene, and Wave 29 regression
evidence remain required.

`wave30-gate` is the single final release-readiness target. It may delegate to
the stabilized `wave29-gate`, but it must also run Wave 30 target validation,
ForcAD validation, archive hygiene, and release archive generation. Wave 30 is
accepted only after exact `timeout 300 make wave30-gate` success under
orchestrator acceptance; no future feature waves are unlocked.

W30-F02 agent validation recorded `timeout 300 make wave30-gate` exit 0 in
4m3.712s on the WSL GNU-timeout/make path. The target produced
`/tmp/sentinel-aml-release/sentinel_aml_release.tar.gz` with 668 files and
SHA-256 `7ee8026ce68da3ca1f59507b19ec077151d06d1229bfafc7b1688cafa43b2fa5`.
This is re-review evidence only; final competition readiness remains
orchestrator-owned.

Final packaging must also record the package path, checksum or equivalent
integrity evidence, and confirmation that generated caches, temporary build
state, local app data, IDE metadata, and non-canonical prompt pools are absent.

## CTF Release Invariants

- ForcAD checker type remains `pfr`.
- Exactly two checker places remain active.
- Place 1 stores flags in `CaseNote.body`.
- Place 2 stores flags in `EDDRecord.confidential_comment`.
- Checker PUT stores flags through normal analyst workflows.
- Checker GET reads only owner-view APIs.
- CHECK/HAVOC remains strong and release-blocking.
- Public attack data remains credential-free and raw-flag-free.
- Exactly five planned vulnerabilities are represented by bounded vulnerable
  build profiles.
- Exactly five accepted reference sploits exist:
  `aml_dedup_preview.py`, `aml_audit_timeline.py`, `aml_related_graph.py`,
  `aml_export_redaction.py`, and `aml_network_room.py`.
- Exactly five reference fix patches exist:
  `aml_dedup_preview.patch`, `aml_audit_timeline.patch`,
  `aml_related_graph.patch`, `aml_export_redaction.patch`, and
  `aml_network_room.patch`.

## Security Release Invariants

- Checker and sploits must not use direct database access, hidden debug/admin
  routes, leaked credentials, shell helpers, or checker-private state.
- Default and fixed profiles must not expose private notes, EDD confidential
  comments, evidence internals, raw audit diffs, hashes, credentials, sessions,
  checker-private state, or raw database rows through side views.
- Reference fixes must preserve business functions while blocking the matched
  exploit; endpoint removal or module disablement is not an acceptable fix.
- DTO/projection allowlists, recursive export redaction, and reference-only
  network-room dossier semantics remain required.

## Final Readiness Boundary

This manifest freezes the release evidence requirements. Sentinel AML becomes
competition-ready only after Wave 30 packaging and release validation record the
required evidence and receive orchestrator acceptance.
