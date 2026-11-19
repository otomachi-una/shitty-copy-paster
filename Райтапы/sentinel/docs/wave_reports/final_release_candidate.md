# Final Release Candidate Manifest

## 1. Summary

W31-F02 records the final release-candidate handoff after W31-F01 produced exact
aggregate gate success for `/usr/bin/timeout 300 make wave30-gate`. The release
candidate package metadata is ready for orchestrator review. Final competition
readiness is not self-accepted and remains blocked until orchestrator release
review records acceptance.

## 2. Implementation Details

No product, checker, sploit, fix, vulnerability-profile, or source-of-truth
requirement behavior changed. The Wave 30 release-readiness manifest remains
the preserved authority for final validation scope.

W31-F01 exact gate evidence:

- Required final gate command: `/usr/bin/timeout 300 make wave30-gate`.
- Agent-validation result: exit 0 in 3m49.270s on 2026-09-05 on the WSL
  GNU-timeout/make path.
- Gate archive output:
  `/tmp/sentinel-aml-release/sentinel_aml_release.tar.gz`.
- Gate archive inventory: 671 files.
- Gate archive SHA-256:
  `bb6b37097cf4739a9c5a8edbdfb650a95ce5763372bb5f3aaa5a3e4e29fa26a7`.

Durable release-candidate artifact metadata:

- Durable artifact path:
  `C:\Users\2005g\.codex\visualizations\2026\09\03\01a0694d-7ad4-78b3-898f-a25d97094366\sentinel-aml-release\sentinel_aml_release.tar.gz`.
- Durable archive inventory: 671 files.
- Durable archive SHA-256:
  `d850a2e0e4111a72f3c2e2ece4ee72814517305ff0931db7616bf45f4a87e7ed`.
- Build command:
  `python -B scripts/build_release_archive.py --output-dir C:\Users\2005g\.codex\visualizations\2026\09\03\01a0694d-7ad4-78b3-898f-a25d97094366\sentinel-aml-release`.
- Archive hygiene command:
  `python -B scripts/check_archive_hygiene.py C:\Users\2005g\.codex\visualizations\2026\09\03\01a0694d-7ad4-78b3-898f-a25d97094366\sentinel-aml-release\sentinel_aml_release.tar.gz`.
- Independent checksum command:
  `Get-FileHash -Algorithm SHA256 C:\Users\2005g\.codex\visualizations\2026\09\03\01a0694d-7ad4-78b3-898f-a25d97094366\sentinel-aml-release\sentinel_aml_release.tar.gz`.

The durable artifact checksum is external release-candidate metadata. It is not
intended to be self-contained inside the archive, because embedding an archive
checksum inside an archived document would change the archive hash.

Release-candidate status:

- Wave 30 final gate: exact aggregate gate success exists in agent validation.
- Release candidate package metadata: ready for orchestrator review.
- Final competition readiness: pending orchestrator acceptance.

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
  exit 0, elapsed 1.747s, durable archive build passed with 671 files,
  SHA-256 `d850a2e0e4111a72f3c2e2ece4ee72814517305ff0931db7616bf45f4a87e7ed`.
- `python -B scripts/check_archive_hygiene.py C:\Users\2005g\.codex\visualizations\2026\09\03\01a0694d-7ad4-78b3-898f-a25d97094366\sentinel-aml-release\sentinel_aml_release.tar.gz` -
  exit 0, elapsed 0.175s.
- `python -B scripts/check_archive_hygiene.py` - exit 0, elapsed 0.178s.
- `Get-FileHash -Algorithm SHA256 C:\Users\2005g\.codex\visualizations\2026\09\03\01a0694d-7ad4-78b3-898f-a25d97094366\sentinel-aml-release\sentinel_aml_release.tar.gz` -
  exit 0, elapsed 0.064s, SHA-256
  `D850A2E0E4111A72F3C2E2ECE4EE72814517305FF0931DB7616BF45F4A87E7ED`.

## 6. Documentation Updated

This file is the final release-candidate manifest for orchestrator review. It
records exact aggregate gate evidence, durable archive path, inventory,
checksum, and the boundary that final competition readiness remains
orchestrator-owned.

## 7. CTF Invariants Checked

No CTF behavior changed. The documented final evidence still requires two
active checker flag stores, five planned vulnerabilities, five reference
sploits, five reference fixes, strong CHECK/HAVOC, exploit-blocking fixes,
anti-coarse-fix coverage, archive hygiene, and reproducible release packaging.

## 8. Security Invariants Checked

No security behavior changed. This manifest does not alter or reinterpret the
fixed-profile visibility boundaries, direct DB prohibition, debug/admin
prohibition, shell-helper prohibition, or side-view leak restrictions.

## 9. Self-Review

This is status and evidence metadata only. It does not alter final gate
coverage or any service behavior. It avoids `/tmp` as the only artifact
reference and does not claim final competition readiness before orchestrator
acceptance.

## 10. Risks / Open Questions

- Open: final competition readiness remains pending orchestrator acceptance.
- Open: the durable artifact path is local to this review workspace; if the
  orchestrator promotes it elsewhere, that promoted path and checksum should be
  recorded as the accepted release artifact.

## 11. Ready for Orchestrator Review

Ready for Orchestrator Review: yes. Final competition readiness accepted: no.
