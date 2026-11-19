# Sentinel AML — Roadmap

This roadmap is the orchestrator-facing dependency plan. It keeps secure normal flows ahead of checker, vulnerability, exploit, and fix work.

## Status Ledger

| Wave | Status | Review note |
| --- | --- | --- |
| Wave 01 | complete | Repository skeleton, ForcAD layout, docs gate, and Wave 01 fixes are complete. |
| Wave 02 | complete | Database/auth/session foundation, toolchain reproducibility, live PostgreSQL auth gate, and documentation canonicalization fixes are complete. |
| Wave 03 | complete | Customer/account/transaction persistence, owner APIs, offline dependency gate, transaction input hardening, and roadmap/duplicate-error fixes are complete. |
| Wave 04 | complete | Deterministic risk, alerts, cases, private-note APIs, and Wave 04 validation gate are complete. |
| Wave 05 | complete | EDD persistence, owner APIs, live integration, visibility regression, and Wave 05 validation gate are accepted. |
| Wave 06 | complete | Projection allowlists, HTTP leak regression, cross-owner authorization matrix, and Wave 06 validation gate are accepted. |
| Wave 07 | complete | Secure dedup metadata, repository discovery, HTTP list/merge-preview endpoints, anti-AML-1 tests, and Wave 07 validation gate are accepted. |
| Wave 08 | complete | Secure audit persistence, owner case timeline API, anti-AML-2 tests, and Wave 08 validation gate are accepted. |
| Wave 09 | complete | Secure graph persistence, repository/API endpoints, projection allowlists, anti-AML-3 tests, and Wave 09 validation gate are accepted. |
| Wave 10 | complete | Secure export and network-room persistence, HTTP APIs, projection allowlists, anti-AML-4/anti-AML-5 tests, and Wave 10 validation gate are accepted. |
| Wave 11 | complete | Checker place 1 PUT/GET for `CaseNote.body`, PFR state split, checker regression tests, and Wave 11 validation gate are complete. |
| Wave 12 | complete | Checker place 2 PUT/GET for `EDDRecord.confidential_comment`, multi-place PFR state split, checker regression matrix, and Wave 12 validation gate are accepted. |
| Wave 13 | complete | Strong CHECK/HAVOC, optional noise/retention, PUT/GET regression preservation, and W13-F01 liveness fixes are accepted by the current-branch `make wave16-gate` aggregate result; `make wave13-gate` is now a historical point-in-time gate. |
| Wave 14 | complete | AML-1 dedup merge-preview vulnerable profile is accepted by current-branch Wave 16 reconciliation; no standalone Wave 14 accepted review artifact is fabricated, and exploit/fix work remains locked to the planned sequence. |
| Wave 15 | complete | AML-2 audit timeline vulnerable profile and checker-discovery liveness fixes are accepted by current-branch Wave 16 reconciliation; no standalone Wave 15 accepted review artifact is fabricated, and exploit/fix work remains locked to the planned sequence. |
| Wave 16 | complete | Orchestrator review host reported `make wave16-gate` exiting 0, accepting the AML-3 `aml3_vulnerable` profile while default graph remains secure and exploit/fix work remains locked. |
| Wave 17 | complete | W17-F01 deterministic wrapper evidence shows `timeout 300 make wave17-gate` exiting 0 after serializing the AML-4 tagged sweep; AML-4 remains only under `aml4_vulnerable`, and exploit/fix work remains locked to the planned sequence. |
| Wave 18 | complete | W18-F01/F02/F03 reconcile AML-5 as accepted after deterministic `timeout 300 make wave18-gate` and archive-hygiene evidence; AML-5 remains only under `aml5_vulnerable`. |
| Wave 19 | complete | Reference exploit `aml_dedup_preview.py` is accepted for AML-1 using public attack data and normal HTTP APIs only; `wave_19_validation_summary.md` records T01/T02/T03 evidence. |
| Wave 20 | complete | Reference exploit `aml_audit_timeline.py` is accepted for AML-2 after W20-F01/W20-F02 reconciliation and an exit-0 `timeout 300 make wave20-gate` re-review; Wave 21 is the next allowed exploit wave, and all fix waves remain locked. |
| Wave 21 | complete | Reference exploit `aml_related_graph.py` is accepted for AML-3 through the related graph EDD summary side view; Wave 22 is the next allowed exploit wave, and all fix waves remain locked. |
| Wave 22 | complete | Reference exploit `aml_export_redaction.py` is accepted for AML-4 through the dispute export linked-evidence side view. |
| Wave 23 | complete | Reference exploit `aml_network_room.py` is accepted for AML-5 through the network-room dossier side view. |
| Wave 24 | complete | AML-1 reference fix artifact, Wave 24 gate, matrix update, exploit-blocked evidence, anti-coarse-fix evidence, and gate-liveness reconciliation are accepted as the prerequisite for Wave 25 work. |
| Wave 25 | complete | AML-2 reference fix artifact, Wave 25 gate, competition matrix update, exploit-blocked evidence, anti-coarse-fix evidence, and documentation alignment are accepted as the prerequisite for Wave 26 work. |
| Wave 26 | complete | AML-3 reference fix artifact, Wave 26 gate, competition matrix update, exploit-blocked evidence, anti-coarse-fix evidence, and documentation alignment are accepted as the prerequisite for Wave 27 work. |
| Wave 27 | complete | AML-4 reference fix artifact, Wave 27 gate, competition matrix update, exploit-blocked evidence, anti-coarse-fix evidence, documentation alignment, and W27-F01/W27-F02 reconciliation are complete as the prerequisite for Wave 28 work. |
| Wave 28 | complete | AML-5 reference fix artifact, Wave 28 gate, competition matrix final fix cells, exploit-blocked evidence, anti-coarse-fix evidence, and documentation recovery are accepted as the prerequisite for Wave 29 work. |
| Wave 29 | complete | Full competition matrix gate plus end-to-end checker/exploit/fix regression evidence are accepted after W29-F01 exact `timeout 300 make wave29-gate` exit-0 evidence and W29-F02 status reconciliation. This does not claim final competition readiness. |
| Wave 30 | historical packaging evidence | `wave30-gate` remains historical release-packaging evidence, including archive hygiene and release archive generation, but it is no longer the current aggregate stability gate. The W32 split keeps service/checker/sploit/fix validation independent from final package promotion. |
| Wave 31 | historical handoff evidence | W31-F02 records durable release-candidate package metadata for review context only. No final release candidate or final competition-readiness acceptance is issued by this ledger. |
| Wave 32 | ready for orchestrator review | Runtime/A-D stability candidate: `ad-stability-gate`, checker scenario inventory, all five sploit/fix matrix cells, vulnerable-profile runner, release-profile Go tests, Go vet/build, ForcAD config, docs tree, and live runtime smoke evidence are recorded without building final archives, player bundles, manifests, or checksums. |
| Wave 33 | ready for orchestrator review | Packaging boundary and allowlist design are documented in `docs/player_admin_packaging_split_plan.md` and `docs/wave_reports/wave_33_packaging_boundary.md`. No final packages are built, and product/checker/sploit/fix/runtime behavior is unchanged. |
| Wave 34 | ready for orchestrator review | Runtime A/D alignment and split candidate validation are frozen in `docs/wave_reports/wave_34_status_freeze.md`: competition runtime profile, real side-view/runtime lifecycle work, live black-box matrix, clean-deploy CHECK/HAVOC, player-service source candidate runtime proof, admin/checker candidate inventory, and final split-package gate evidence are recorded. No final release archive, final player/admin archive, manifest, checksum set, promoted image, or final competition-readiness acceptance is issued. |
| Wave 35+ | artifact-first source/admin outputs under review | Packaging/release promotion is conditional on Wave 34 acceptance. W34-P01 defines `sentinel-aml-player-source.tar.gz` as the primary participant artifact, `sentinel-aml-admin-organizer.tar.gz` as organizer-only, and `sentinel-aml-player-binary.tar.gz` as non-primary runtime convenience. Full repository zip is never a player artifact. Later review must still accept or reject promotion. |

## Dependency Roadmap

| Wave | Theme | Prerequisites | Unlocks |
| --- | --- | --- | --- |
| W01 | Repository, ForcAD, and docs foundation | none | W02 |
| W02 | PostgreSQL users/sessions and auth API | W01 closed | W03 |
| W03 | Customer/account/transaction domain persistence and owner APIs | W02 closed | W04 |
| W04 | Risk scoring, alerts, and owner case workflow | W03 fixes closed | W05, W06, W11 |
| W05 | EDD workflow and confidential review records | W04 closed | W06, W12 |
| W06 | Secure visibility/projection matrix | W04 and W05 closed | W07-W10 |
| W07 | Dedup review secure baseline | W06 closed | W14 |
| W08 | Audit timeline secure baseline | W06 closed | W15 |
| W09 | Related-entity graph secure baseline | W06 closed | W16 |
| W10 | Export redaction and network-room secure baselines | W06 closed | W17, W18 |
| W11 | Checker PUT/GET for `CaseNote.body` | W04, W06 closed | W13 |
| W12 | Checker PUT/GET for `EDDRecord.confidential_comment` | W05, W06 closed | W13 |
| W13 | Checker integration, CHECK/HAVOC, idempotency, retention | W11 and W12 closed | W14-W18 |
| W14 | Planned vulnerability: dedup preview | W07 and W13 closed | W19 |
| W15 | Planned vulnerability: audit timeline | W08 and W13 closed | W20 |
| W16 | Planned vulnerability: related graph | W09 and W13 closed | W21 after Wave 16 acceptance |
| W17 | Planned vulnerability: export redaction | W10 and W13 closed | W22 after Wave 17 acceptance |
| W18 | Planned vulnerability: network room | W10 and W13 closed | W19 as the next allowed wave after all vulnerable-checker cells are accepted |
| W19 | Reference exploit `aml_dedup_preview.py` | W14 closed and W18 accepted | W20 after W19 acceptance |
| W20 | Reference exploit `aml_audit_timeline.py` | W15 closed and W19 accepted | W21 after W20 acceptance |
| W21 | Reference exploit `aml_related_graph.py` | W16 closed and W20 accepted | W22 after W21 acceptance |
| W22 | Reference exploit `aml_export_redaction.py` | W17 closed and W21 accepted | W23 after W22 acceptance |
| W23 | Reference exploit `aml_network_room.py` | W18 accepted and W22 accepted | W24 after W23 acceptance |
| W24 | Reference fix for dedup preview | Wave 23 accepted and W19 exploit evidence captured | W25 after W24 acceptance |
| W25 | Reference fix for audit timeline | Wave 24 accepted and W20 exploit evidence captured | W26 after W25 acceptance |
| W26 | Reference fix for related graph | Wave 25 accepted and W21 exploit evidence captured | W27 after W26 acceptance |
| W27 | Reference fix for export redaction | Wave 26 accepted and W22 exploit evidence captured | W28 after W27 acceptance |
| W28 | Reference fix for network room | Wave 27 accepted and W23 exploit evidence captured | W29 after W28 acceptance |
| W29 | Regression matrix and anti-coarse-fix validation | W24-W28 closed | W30 after Wave 29 acceptance |
| W30 | Historical final validation and packaging evidence | W29 accepted | W31 durable handoff context; superseded for active stability by W32 |
| W31 | Historical release-candidate handoff metadata | W30 review evidence | W32 runtime/package split reconciliation |
| W32 | Runtime/A-D stability candidate | W29 accepted; W30/W31 packaging evidence reviewed as historical context | W33 packaging boundary design after orchestrator review |
| W33 | Packaging boundary and allowlist design | W32 runtime-stability review outcome | W34 runtime/package-candidate proof; W35+ final package promotion only after Wave 34 acceptance |
| W34 | Runtime A/D alignment and split candidate proof | W33 boundary accepted | W35 packaging/release promotion only after Wave 34 acceptance |
| W35+ | Final packaging/release promotion | Wave 34 accepted | final release package review only after artifact-first archive/manifest/checksum evidence, static scans, and orchestrator approval |

## Cross-Wave Rules

- Secure normal workflows must exist and have negative tests before a planned vulnerability wave can introduce a controlled weakness.
- Reference exploit scripts must not exist before their corresponding vulnerability wave is accepted.
- Reference fixes must not disable whole features, remove checker paths, or mask failed validation.
- Checker logic must use normal HTTP product APIs only.
- No wave may add debug/admin shortcuts, direct DB checker access, public credentials, artificial flag fields, or broad DB model serialization.
- Documentation, tests, and handoff reports must be updated in the same wave that changes behavior or validation gates.
- Stability gates validate service, checker, sploit, fix, vulnerable-profile, Go, docs, and ForcAD behavior without building final archives; package/release gates own archive generation, player bundles, manifests, checksums, and sanitization. The canonical delivered player boundary is source-based: `sentinel-aml-player-source.tar.gz` is the primary participant artifact, `sentinel-aml-admin-organizer.tar.gz` is organizer-only, and `sentinel-aml-player-binary.tar.gz` is non-primary runtime convenience. Binary-only is not sufficient for classic A/D distribution, and full repository zip is never a player artifact. `make artifacts` is the artifact-first package-output builder, `make artifact-gate` validates archive inventories/checksums and the source/admin component contract, and `make artifact-first-gate` builds then tests the exact transfer artifacts and writes `out/artifact-first-validation-summary.json` while marking live runtime obligations as `external-required` when not run locally. These gates do not make final release acceptance claims.
- Wave 09 is complete after W09-T01, W09-T02, W09-T03, and W09-T04.
- Wave 10 is complete after W10-T01, W10-T02, W10-T03, W10-T04, and W10-T05.
- Wave 11 is complete after W11-T01, W11-T02, W11-T03, W11-T04, and W11-T05.
- Wave 12 is complete after W12-T01, W12-T02, W12-T03, W12-T04, W12-T05, and AD-C0 accepted the two-place checker.
- Place 1 and place 2 checker PUT/GET are active after Wave 12.
- ADR-0003 distinguishes point-in-time historical wave gates from current-branch aggregate gates. Historical gates such as `make wave13-gate`, `make wave14-gate`, and `make wave15-gate` may reject later-wave vulnerability markers when run on this branch; that does not override the current `make wave16-gate` aggregate acceptance.
- The orchestrator review host reported `make wave16-gate` exiting 0. That current-branch aggregate result reconciles Waves 13 through 16 as complete for this active branch.
- No standalone Wave 14 or Wave 15 accepted review artifact is fabricated. Their historical evidence gap is recorded here, while the current branch relies on the Wave 16 aggregate gate and competition matrix gate.
- Wave 17 AML-4 export-redaction vulnerable-profile work is complete after
  W17-F01 recorded `timeout 300 make wave17-gate` exiting 0 with the
  deterministic serialized tagged sweep.
- Wave 18 AML-5 network-room vulnerable-profile work is complete after
  W18-F01 replaced the non-terminating aggregate tagged sweep with the
  deterministic package-by-package AML-5 runner, W18-F02 added archive hygiene
  to `make wave18-gate`, and W18-F03 reconciled the status ledgers using
  `timeout 300 make wave18-gate` and archive-hygiene exit-0 evidence.
- Wave 19 AML-1 reference exploit work is accepted after orchestrator review.
  Wave 20 AML-2 reference exploit work is accepted after W20-F01/W20-F02
  reconciliation and exit-0 `timeout 300 make wave20-gate` re-review evidence.
  Wave 21 AML-3 reference exploit work is accepted after orchestrator review.
  Wave 22 AML-4 reference exploit work is accepted after orchestrator review.
  Wave 23 AML-5 reference exploit work is accepted after orchestrator review.
  Wave 24 AML-1 reference fix work is complete. Wave 25 AML-2 reference fix
  work is complete after orchestrator acceptance. Wave 26 AML-3 reference fix
  work is complete after orchestrator acceptance. Wave 27 AML-4 reference fix
  work is complete after orchestrator acceptance. Wave 28 AML-5 reference fix
  work is complete after orchestrator acceptance. Wave 29 is complete after
  W29-F01 exact aggregate gate evidence and orchestrator acceptance, unlocking
  only Wave 30 source-of-truth freeze and release validation.
- W22-T01 implemented `aml_export_redaction.py`, W22-T02 implemented the Wave
  22 gate and competition matrix alignment, and W22-T03 recorded
  documentation/evidence alignment before Wave 22 acceptance.
- W23-T01 implemented `aml_network_room.py`, W23-T02 implemented the Wave 23
  gate and final reference-exploit competition matrix alignment, and W23-T03
  records documentation/status alignment. Wave 23 is now accepted and unlocks
  only Wave 24 for AML-1 reference-fix work.
- W24-T01 added `fixes/sentinel_aml/aml_dedup_preview.patch`, W24-T02 added
  `scripts/check_wave24_gate.py` and made AML-1 fix cells concrete in the
  competition matrix, W24-T03 strengthened exploit-blocked and anti-coarse-fix
  evidence, and W24-F01 implemented the gate-liveness fix after the first
  aggregate review timed out in the release/offline Go test step. Wave 24 is
  complete for the current Wave 25 sequence. W25-T01 added
  `fixes/sentinel_aml/aml_audit_timeline.patch`, W25-T02 added the Wave 25
  gate and made only AML-2 fix cells concrete in addition to AML-1, and W25-T03
  strengthened AML-2 exploit-blocked and anti-coarse-fix evidence. Wave 25 is
  accepted and unlocks only Wave 26. W26-T01 added
  `fixes/sentinel_aml/aml_related_graph.patch`, W26-T02 added the Wave 26 gate
  and made only AML-3 fix cells concrete in addition to AML-1/AML-2, W26-T03
  strengthened AML-3 exploit-blocked and anti-coarse-fix evidence, and W26-T04
  records documentation/status alignment. W26-F01 replaces the opaque aggregate
  Go test sweep in `wave26-gate` with a deterministic package-by-package
  release/offline runner. Wave 26 is accepted and unlocked only Wave 27.
  W27-T01 added `fixes/sentinel_aml/aml_export_redaction.patch`, W27-T02 added
  the Wave 27 gate and made only AML-4 fix cells concrete in addition to
  AML-1/AML-2/AML-3, and W27-T03 strengthened AML-4 exploit-blocked and
  anti-coarse-fix evidence. W27-F01 stabilized the package-by-package
  release/offline Go runner after aggregate review found a liveness blocker,
  and W27-F02 reconciled the Wave 27 ledgers after gate-fix evidence. Wave 27
  is complete and unlocked only Wave 28. W28-F01 added
  `fixes/sentinel_aml/aml_network_room.patch`, W28-F02 added the Wave 28 gate
  and made AML-5 fix cells concrete in addition to AML-1 through AML-4, and
  W28-F03 records documentation/status recovery. Wave 28 is complete and
  unlocked only Wave 29. W29-T01 added the full competition matrix gate, W29-T02
  added end-to-end checker/exploit/fix regression evidence, and W29-T03 aligned
  documentation for Wave 29 implemented-under-review status. Orchestrator review
  then marked Wave 29 `needs fixes` because the aggregate gate timed out.
  W29-F01 recorded exact GNU-style `timeout 300 make wave29-gate` exit-0
  evidence, W29-F02 reconciled the status ledgers for re-review, and Wave 29 is
  now accepted as the prerequisite for Wave 30. W30-T01 adds the
  source-of-truth freeze and release-readiness manifest, W30-T02 adds
  deterministic release archive packaging and generated-archive hygiene, W30-T03
  records final ForcAD/checker/exploit/fix matrix evidence, W30-T04 reconciles
  DoD/risk/status closure, and W30-F02 adds `wave30-gate` as the historical
  package-inclusive acceptance command. W31-F02 records durable
  release-candidate metadata for review context only. Wave 32 separates runtime
  stability from package promotion: W32-T01 adds archive-free
  `ad-stability-gate`, W32-T02 records full checker scenario evidence, W32-T03
  records the five-sploit/five-fix matrix, W32-T04 records live runtime smoke
  evidence, and W32-T05 reconciles these ledgers. Wave 32 is ready for
  orchestrator review as a runtime/A-D stability candidate only. Final archive
  generation, player/admin packaging, code sanitization, leak cleanup, manifest
  generation, checksum generation, and package promotion are deferred to
  Wave 33+ and remain orchestrator-owned. W33-T01 documents the
  organizer-full, player-service, admin/checker, and optional evidence package
  boundaries without building packages; actual package builders, sanitization,
  leak scans, manifests, checksums, and promotion remain future work. Wave 34
  freezes runtime A/D alignment and split candidate proof only; final
  distribution promotion is deferred to Wave 35+ after Wave 34 acceptance.
  W33-AF1 adds `scripts/build_artifacts.py`, `scripts/check_artifacts.py`,
  `make artifacts`, and `make artifact-gate` so exact player and
  admin/organizer transfer archives are generated under `out/` with matching
  manifests and SHA-256 checksums. W34-P01 canonicalizes the player side as
  `sentinel-aml-player-source.tar.gz`, the primary source-based participant
  artifact for patching and rebuilding. `sentinel-aml-admin-organizer.tar.gz`
  remains organizer-only, and `sentinel-aml-player-binary.tar.gz` is retained
  only as non-primary runtime convenience; binary-only is not sufficient for
  classic A/D, and full repository zip is never a player artifact.
  W33-AF5 adds the aggregate `artifact-first-gate` so transfer artifacts are
  built before byte hygiene, manifest/checksum, runtime profile, and admin
  matrix evidence checks run. AF-F03/AF-F04 stamp the validation summary with
  current-run player/admin artifact SHA-256 values and explicit live/external
  runtime smoke, checker CHECK/HAVOC, five-sploit, five-fix, and matrix
  statuses while keeping `PACKAGING_STATUS.json` player-facing and operational.
  Exact artifact runtime proof remains in the external validation summary when
  live validation is not run locally. AF-F05/FH-04 add a clean allowlist-built
  internal repository-submission zip that excludes generated outputs and nested
  transfer archives while referencing transfer artifacts by checksum only. This
  is artifact-output evidence under review, not final competition-readiness
  acceptance.
- Later waves must preserve the owner-only checker paths for `CaseNote.body` and `EDDRecord.confidential_comment`.

## Historical Review Notes

The current ledger above is authoritative. Prior review states are retained only for legacy gate context: `| Wave 05 | needs fixes |`, `| Wave 06 | needs fixes |`, `| Wave 07 | needs fixes |`, `| Wave 08 | needs fixes |`, `| Wave 09 | needs fixes |`, `| Wave 10 | needs fixes |`, and `| Wave 11 | needs fixes |`. Historical Wave 11 remains `needs fixes` until W11-T01, W11-T02, W11-T03, W11-T04, and W11-T05 pass legacy context checks.
