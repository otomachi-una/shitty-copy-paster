# Wave 31 Release Candidate Handoff

## 1. Summary

W31-F02 produces the dedicated Wave 31 release-candidate handoff after exact
final aggregate gate success from W31-F01. It records durable artifact
metadata, checksum evidence, inventory count, gate command evidence, and the
competition-readiness boundary. The release candidate metadata is ready for
orchestrator review; final competition readiness is not self-accepted.

## 2. Implementation Details

- Preserved the Wave 30 release-readiness manifest and final aggregate gate.
- Reused W31-F01 exact gate evidence:
  `/usr/bin/timeout 300 make wave30-gate` exited 0 in 3m49.270s.
- Built a fresh release archive outside `/tmp` and outside the repository:
  `C:\Users\2005g\.codex\visualizations\2026\09\03\01a0694d-7ad4-78b3-898f-a25d97094366\sentinel-aml-release\sentinel_aml_release.tar.gz`.
- Validated the generated archive with `scripts/check_archive_hygiene.py`.
- Calculated the checksum independently with `Get-FileHash`.

Durable artifact metadata:

- Path:
  `C:\Users\2005g\.codex\visualizations\2026\09\03\01a0694d-7ad4-78b3-898f-a25d97094366\sentinel-aml-release\sentinel_aml_release.tar.gz`.
- Inventory: 671 files.
- SHA-256:
  `d850a2e0e4111a72f3c2e2ece4ee72814517305ff0931db7616bf45f4a87e7ed`.

The checksum is external release-candidate metadata, not a value embedded in
the archive itself. Embedding the archive hash inside an archived document
would change the archive hash.

## 3. Files Changed

- `docs/wave_reports/final_release_candidate.md`
- `docs/wave_reports/wave_31_release_candidate_handoff.md`
- `docs/definition_of_done.md`
- `docs/13_roadmap.md`
- `docs/source_of_truth_map.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`

## 4. Tests Added

No tests were added for W31-F02. This wave records release-candidate metadata
and status only.

## 5. Tests Run

- `/usr/bin/timeout 300 make wave30-gate` - cited from W31-F01 same-snapshot
  evidence: exit 0 in 3m49.270s.
- `python -B scripts/build_release_archive.py --output-dir C:\Users\2005g\.codex\visualizations\2026\09\03\01a0694d-7ad4-78b3-898f-a25d97094366\sentinel-aml-release` -
  exit 0, elapsed 1.747s, 671 files, SHA-256
  `d850a2e0e4111a72f3c2e2ece4ee72814517305ff0931db7616bf45f4a87e7ed`.
- `python -B scripts/check_archive_hygiene.py C:\Users\2005g\.codex\visualizations\2026\09\03\01a0694d-7ad4-78b3-898f-a25d97094366\sentinel-aml-release\sentinel_aml_release.tar.gz` -
  exit 0, elapsed 0.175s.
- `python -B scripts/check_archive_hygiene.py` - exit 0, elapsed 0.178s.
- `Get-FileHash -Algorithm SHA256 C:\Users\2005g\.codex\visualizations\2026\09\03\01a0694d-7ad4-78b3-898f-a25d97094366\sentinel-aml-release\sentinel_aml_release.tar.gz` -
  exit 0, elapsed 0.064s, SHA-256
  `D850A2E0E4111A72F3C2E2ECE4EE72814517305FF0931DB7616BF45F4A87E7ED`.

## 6. Documentation Updated

- `docs/wave_reports/final_release_candidate.md` records durable artifact
  metadata and marks the release candidate metadata ready for orchestrator
  review.
- `docs/definition_of_done.md`, `docs/13_roadmap.md`, and
  `docs/source_of_truth_map.md` distinguish release-candidate handoff from
  final orchestrator acceptance.
- `docs/14_agent_execution_log.md` and `docs/15_risk_register.md` record the
  W31-F02 evidence and remaining acceptance boundary.

## 7. CTF Invariants Checked

- Two active checker flag stores remain required.
- Five planned vulnerabilities, five reference sploits, and five reference
  fixes remain traceable through the final gate evidence.
- CHECK/HAVOC, exploit-blocking fixes, anti-coarse-fix coverage, ForcAD
  validation, archive hygiene, and reproducible packaging remain part of the
  release-candidate evidence.

## 8. Security Invariants Checked

- No product behavior, checker logic, sploit behavior, fix patch semantics, or
  vulnerable build profile changed.
- No document normalizes debug/admin routes, direct DB access, shell helpers,
  leaked credentials, public flag data, or private-field exposure through fixed
  side views.

## 9. Self-Review

This wave records durable package metadata and status only. It avoids using
`/tmp` as the only artifact reference and avoids claiming final competition
readiness without orchestrator acceptance. No source-of-truth requirement was
changed.

## 10. Risks / Open Questions

- Orchestrator acceptance remains required before final competition readiness
  can be stated.
- The durable artifact path is local to this review workspace; if the
  orchestrator promotes it elsewhere, that promoted path and checksum should be
  recorded as the accepted release artifact.

## 11. Ready for Orchestrator Review

Ready for Orchestrator Review: yes. Final competition readiness accepted: no.
