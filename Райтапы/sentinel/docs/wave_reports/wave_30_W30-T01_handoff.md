# W30-T01 Handoff - Source-of-Truth Freeze And Release Readiness Manifest

## 1. Summary

Created the Wave 30 release-readiness manifest and aligned the allowed
source-of-truth ledgers for Wave 30 implementation under review. Final
competition readiness remains pending Wave 30 packaging and release validation.

## 2. Implementation Details

- Added `docs/wave_reports/wave_30_release_readiness_manifest.md`.
- Updated the source-of-truth map to name the manifest as release-readiness
  freeze authority.
- Updated Definition of Done to require the Wave 30 manifest and post-freeze
  ADRs for any source-of-truth changes.
- Updated roadmap and waves ledgers so Wave 29 is complete and Wave 30 is
  implemented under review.
- Marked prompt pools, handoffs, validation summaries, and archived material as
  historical/reference-only unless an ADR promotes a requirement.

## 3. Files Changed

- `docs/definition_of_done.md`
- `docs/source_of_truth_map.md`
- `docs/13_roadmap.md`
- `docs/waves.md`
- `docs/wave_reports/wave_30_release_readiness_manifest.md`
- `docs/wave_reports/wave_30_W30-T01_handoff.md`

## 4. Tests Added

No tests were added. This is a documentation and source-of-truth freeze task.

## 5. Tests Run

- `python -B scripts/check_docs_tree.py` - exit 0.
- `python -B scripts/check_archive_hygiene.py` - exit 0.

## 6. Documentation Updated

The manifest lists authoritative docs for API, database, checker, flags,
vulnerabilities, views, workers, tests, deployment, status, risks, and
completion criteria. It also lists exact release evidence for final packaging.

## 7. CTF Invariants Checked

- ForcAD checker type remains `pfr` with two active places.
- Place 1 remains `CaseNote.body`.
- Place 2 remains `EDDRecord.confidential_comment`.
- Checker uses normal owner-view APIs.
- Strong CHECK/HAVOC, five vulnerabilities, five sploits, five fixes, and
  flag-lifetime expectations remain required.

## 8. Security Invariants Checked

- No fixed-profile side-view private-data leak is normalized.
- Direct DB, debug/admin, broad serialization, endpoint-removal fixes, and
  checker-private/public attack-data boundary violations remain forbidden.

## 9. Self-Review

The work is documentation-only and stays inside the W30-T01 file scope. It
does not change code, migrations, checker behavior, sploit behavior, fix patch
semantics, public attack-data schema, or config semantics. The manifest freezes
requirements without claiming final competition readiness.

## 10. Risks / Open Questions

- Final package checks, checksums, and release-candidate handoff remain pending
  Wave 30 packaging/release validation.
- Any post-freeze requirement change must go through an ADR and rerun affected
  validation.

## 11. Ready for Orchestrator Review

yes
