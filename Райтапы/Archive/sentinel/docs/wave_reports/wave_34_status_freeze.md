# Wave 34 Status Freeze

Status: canonical status freeze for runtime/package boundary; ready for
orchestrator review.

## Purpose

This document is the Wave 34 status authority. It reconciles README, roadmap,
source-of-truth, Definition of Done, risk, execution-log, and Wave 34 report
language so maintainers can distinguish runtime A/D readiness from packaging
and distribution readiness.

Older wave reports remain evidence. They do not promote final distribution
unless this freeze, `docs/source_of_truth_map.md`, and a later orchestrator
review say so explicitly.

## Canonical State

| Track | State | Authority |
| --- | --- | --- |
| Runtime A/D alignment | Ready for orchestrator review | Wave 34 live/runtime evidence plus existing `ad-stability-gate` evidence. |
| Competition runtime build path | Ready for orchestrator review | `make competition-runtime-build` with the neutral competition policy tag set. |
| Live black-box A/D matrix | Ready for orchestrator review | `scripts/check_live_competition_matrix.py --run` evidence. |
| Clean-deploy CHECK/HAVOC | Ready for orchestrator review | `scripts/check_live_checker_clean_deploy.py --run` evidence. |
| Player-service source candidate | Runtime-proven candidate, not final release artifact | W34 package runtime proof and final split-package gate. |
| Admin/checker candidate | Inventory-checked candidate, not final release artifact | W34 admin package preparation and final split-package gate. |
| Final release archive | Not issued | No Wave 34 gate produces release archives. |
| Final player/admin archive | Not issued | Candidate trees only; no promoted distribution archive. |
| Manifest/checksum set | Not issued | Deferred to a later packaging/release wave. |
| Final competition readiness | Pending orchestrator packaging/release review | Runtime evidence is necessary but not sufficient for final readiness. |

## Evidence Cited

- W34-T01: `docs/wave_reports/wave_34_competition_runtime_profile.md`
  records `make competition-runtime-build` and the explicit competition policy
  tag set; it also states no final player archive, release manifest, checksum,
  or promoted image is produced.
- W34-T02: `docs/wave_reports/wave_34_player_package_runtime_proof.md`
  records player source candidate runtime proof: exit `0`, elapsed `38.360s`,
  311-file candidate, 385-member hygiene scan, offline Go test/build,
  Compose validation, migrations, API/worker smoke, and no final archive,
  manifest, checksum, or image push.
- W34-T03: `docs/wave_reports/wave_34_network_room_lifecycle.md` records
  deterministic worker room lifecycle evidence, including runtime smoke exit
  `0` and idempotent room materialization metrics.
- W34-T04: `docs/wave_reports/wave_34_final_split_package_gate.md` records
  `/usr/bin/timeout 300 make final-split-package-gate` exit `0`, host elapsed
  `147.199s`, runner elapsed `146.706s`, with separate `player-service`,
  `admin-checker`, and `organizer-internal` statuses and
  `final_archives_created: false`.
- W34-T05: `docs/08_checker_design.md` records
  `python -B scripts\check_live_checker_clean_deploy.py --run --python python
  --go go --docker docker --json-output tmp\live-checker-clean-deploy.json`
  exit `0`, elapsed `18.094s`, checker `check` exit `101` (`OK`), and checker
  `havoc` exit `101` (`OK`).
- Existing W34 runtime continuity evidence in
  `docs/wave_reports/wave_34_product_surface_hardening.md` records
  `/usr/bin/timeout 300 make wave33-gate` exit `0` in `130.900s` and
  `/usr/bin/timeout 300 make ad-stability-gate` exit `0` in `94.144s`.

## Preserved Concept

The project concept remains unchanged:

- natural business data stores back the active checker places;
- checker GET uses owner-view APIs only;
- planned competition behavior is expressed as bounded side-view business
  projection flaws, not generic debug/admin bypasses;
- organizer reference attacks and reference fixes remain internal evidence;
- CHECK/HAVOC must stay strong enough to catch coarse feature-removal fixes;
- player-facing artifacts must not disclose the intended challenge map,
  checker internals, reference attacks, reference fixes, private state, or
  wave-review history.

## Packaging Boundary

Wave 34 proves candidate trees and runtime paths. It does not publish final
distribution artifacts. Any metadata inside a generated candidate that marks
runtime readiness is candidate-local proof metadata only; it is not a release
acceptance, archive issuance, manifest, checksum, image push, or final
competition-readiness decision.

Wave 35 or a later packaging/release wave may start only after Wave 34 is
accepted. That wave must choose the final distribution wrapper, regenerate from
the proven inputs, scan the final artifacts, produce manifests/checksums if
required, and preserve the organizer/player/admin split.

## Historical Statements

Statements in earlier reports that call a candidate "final" are historical
candidate-generation language unless this freeze explicitly promotes them.
For Wave 34, "final split-package gate" means the final aggregate validation
gate for split candidate tracks, not a final package release.
