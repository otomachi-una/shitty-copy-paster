# Sentinel AML — Definition of Done

Sentinel AML is done only when the implementation, checker, exploits, fixes, tests, and documentation satisfy the repository source-of-truth map and ForcAD contract.

## Wave 01 Done

- Canonical Sentinel AML docs exist at exact filenames.
- Go API and worker placeholders build.
- ForcAD config validates as `sentinel_aml`, `pfr`, two places, two puts, two gets.
- Checker and sploit directories exist and remain separate.
- No product API, migration, checker lifecycle behavior, vulnerability, exploit, reference fix, debug endpoint, or direct database shortcut exists.
- Validation scripts and tests pass.

## Later Completion

Later waves must define their own done criteria before implementing domain behavior, auth, persistence, checker logic, vulnerabilities, exploits, and fixes.

## Runtime Stability Candidate

Wave 32 can be reviewed independently from final packaging when runtime and
A/D behavior are proven by archive-free evidence:

- `timeout 300 make ad-stability-gate` exits 0 in the target environment;
- checker tests explicitly cover both flag stores, public attack-data
  separation, and CHECK/HAVOC scenarios;
- all five vulnerable profiles, all five reference sploits, and all five
  reference fixes are present in the competition matrix with fixed-checker,
  exploit-blocked, and anti-coarse-fix evidence;
- release-profile Go tests, Go vet/build, docs tree, and ForcAD config
  validation pass without release archive creation;
- runtime smoke starts PostgreSQL-backed migrations, API health, worker
  restart paths, and representative customer/account/transaction/case/EDD
  flows through normal APIs;
- evidence is recorded in `docs/wave_reports/wave_32_stability_summary.md`,
  `docs/wave_reports/wave_32_checker_validation.md`,
  `docs/wave_reports/wave_32_sploit_fix_matrix.md`, and
  `docs/wave_reports/wave_32_runtime_smoke.md`.

Wave 32 stability acceptance does not create or accept a final release archive,
player bundle, final manifest, checksum set, sanitized player/admin package, or
final competition-readiness decision.

## Competition Readiness

Sentinel AML is not competition-ready merely because the five vulnerability,
exploit, and reference-fix cells are concrete. Final readiness also requires:

- clean deployment startup from a future sanitized player/admin package;
- migrations applying cleanly to the target database;
- core analyst workflows for auth, customer, account, transaction, alerts,
  cases, case notes, EDD, dedup, audit, graph, export, and network rooms;
- Wave 29 orchestrator acceptance of the full competition matrix gate and
  end-to-end checker/exploit/fix regression evidence;
- Wave 32 archive-free runtime/A-D stability review evidence;
- Wave 33+ player/admin packaging, code sanitization, player-facing leak
  cleanup, final package validation, final manifest generation, and checksum
  metadata;
- two active checker flag stores for `CaseNote.body` and
  `EDDRecord.confidential_comment`;
- checker PUT/GET working for all active places through normal owner-view APIs;
- five accepted reference sploits and five accepted reference fix artifacts;
- planned vulnerabilities reproducible only in their bounded vulnerable build
  profiles;
- reference exploits extracting flags only from the intended side views;
- reference fixes blocking matched exploits while keeping fixed checker and
  business features green;
- strong CHECK/HAVOC coverage for dedup, audit, graph, export, network room,
  case notes, and EDD, including coarse-patch rejection;
- package hygiene, ForcAD validation, source-of-truth consistency, and no
  hidden debug/admin, direct DB checker, public credential, or broad
  serialization shortcut.
- retention behavior that respects the configured flag lifetime assumptions.

## Final Pre-Review State

Wave 34 is ready for orchestrator review as runtime A/D alignment plus split
candidate proof after the status freeze in
`docs/wave_reports/wave_34_status_freeze.md`. The current accepted/pending
split is:

- runtime A/D readiness evidence: ready for orchestrator review;
- competition runtime build path: ready for orchestrator review;
- player-service source candidate: runtime-proven candidate only;
- admin/checker candidate: inventory-checked candidate only;
- final release archive: not issued;
- final player/admin archive: not issued;
- manifest/checksum set: not issued;
- final competition readiness: pending later packaging/release review.

Wave 30/W31 package-inclusive artifacts remain historical review context. Wave
32 remains archive-free runtime/A-D stability context. Wave 33 remains
packaging boundary/candidate-builder context. Wave 34 proves candidate trees
and runtime paths but does not promote a final distribution artifact. Final
package acceptance and final competition acceptance remain orchestrator-only
after Wave 35+ packaging promotion, final artifact scans, manifest/checksum
generation if required, and release review.

## Source-of-Truth Freeze

The Wave 30 release-readiness manifest remains historical package-inclusive
review context. Wave 32 reconciles the active source-of-truth map so runtime
stability is reviewed before package promotion. Wave 34 freezes the active
runtime/package boundary in `docs/wave_reports/wave_34_status_freeze.md`.
After W34-T06, source-of-truth changes require a new ADR or authorized
later-wave ledger update that identifies the affected document, CTF/security
invariant, validation commands, and release-packaging impact. Review artifacts,
handoffs, validation summaries, and prompt pools remain historical/reference-only
unless an ADR promotes a requirement into the authoritative source-of-truth map.
