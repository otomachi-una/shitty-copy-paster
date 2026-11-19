# Wave 33 Player Docs

## Summary

W33-T05 adds sanitized participant-facing run documentation under
`packaging/player/`. The docs explain how to start Sentinel AML, verify API
health, configure persistence, inspect logs, and troubleshoot common runtime
issues without disclosing organizer-only challenge structure or validation
evidence.

No service behavior, checker behavior, sploits, fixes, migrations, Docker
runtime, candidate builders, or organizer evidence changed in this task.

## Participant Docs

- `packaging/player/README.md` provides service overview, runtime
  requirements, Compose startup, health probes, configuration, persistence
  notes, and a normal AML product workflow.
- `packaging/player/TROUBLESHOOTING.md` provides startup, readiness, database,
  migration, worker, authorization, persistence, and log-inspection guidance.

These files are ready to be copied into a future player-service candidate tree.
The current W33-T04 builder was not changed in this task because the allowed
scope is documentation-only.

## Banned-Term Review

The participant docs were checked for:

- `AML-1` through `AML-5`;
- `aml1` through `aml5`;
- checker terminology;
- flag and flag-store terminology;
- exploit/sploit terminology;
- fixes terminology;
- anti-AML test terminology;
- wave history;
- internal gate terminology;
- `attack_info`;
- `public_attack_data`;
- `LEAK_TARGET`;
- `MUST_NOT_LEAK`;
- `checker_secret`;
- `vulnerable`.

No matches were found under `packaging/player/`.

## Allowed Product Terms

The docs intentionally retain neutral product and operations terminology:

- Sentinel AML;
- anti-money-laundering;
- analysts;
- customers;
- accounts;
- transactions;
- alerts;
- cases;
- case notes;
- due diligence;
- audit activity;
- entity relationships;
- network-room reviews;
- redacted case summaries;
- health checks;
- readiness;
- migrations;
- PostgreSQL;
- Docker Compose.

## Tests Run

- `python -B scripts\check_player_bundle_hygiene.py packaging\player` -
  exit 0; scanned 2 candidate members.
- `rg -n -i "aml-[1-5]|aml[1-5]|checker|flag|flag store|exploit|sploit|fixes|anti-aml|wave|internal gate|attack_info|public_attack_data|LEAK_TARGET|MUST_NOT_LEAK|checker_secret|vulnerable" packaging\player` -
  exit 1, no matches.

## CTF and Security Invariants

- The docs do not describe intended vulnerability classes, checker places, flag
  stores, reference sploits, reference fixes, anti-coarse-fix controls, wave
  history, or internal gate evidence.
- The docs do not contain checker secrets, sample flags, hardcoded credentials,
  attack-info schemas, or private organizer state.
- The docs are limited to participant runtime use: startup, ports, health,
  persistence, normal product flow, and troubleshooting.

## Risks

- The participant docs are staged under `packaging/player/` but are not yet
  automatically copied by `scripts/build_player_bundle.py`; that should be wired
  in by a packaging task with script-edit scope.
- The docs assume Compose or Go/PostgreSQL local operation. Final package
  formats may need small path adjustments once source versus binary/image
  delivery is chosen.

## Ready for Review

Yes, for sanitized participant README and troubleshooting documentation.
