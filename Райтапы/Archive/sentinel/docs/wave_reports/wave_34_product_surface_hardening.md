# Wave 34 Product Surface Hardening

Status: implemented under review.

## Summary

Wave 34 hardens the generated player-service source candidate without changing
organizer runtime behavior or A/D evidence. The builder now stages source with
product-neutral policy names for internal runtime variants and removes the last
player hygiene allowlist exception. W34-T02 then proves the source-delivery
runtime path in `docs/wave_reports/wave_34_player_package_runtime_proof.md`.

## Before/After Inventory

Before W34, the player candidate passed the Wave 33 denylist but still exposed
internal source vocabulary such as `*_profile_*.go`, `ProfileEnabled`,
`ForProfile`, `ExportProfileData`, `ExportProfileMaps`, and
`LinkedCaseProfileData`. The generated hygiene allowlist also allowed the Go
standard-library `flag` token in `cmd/aml-api/main.go`.

After W34, generated player source uses policy-oriented names such as
`dedup_policy_case_match.go`, `audit_policy_detail.go`,
`export_policy_linked_case.go`, `graph_policy_entity_review.go`,
`network_room_policy_detail.go`, and `dossier_policy_room_detail.go`. Helper
identifiers are rewritten to `*Policy*` equivalents in the staged copy only.
The generated player hygiene allowlist is empty.

## Candidate Evidence

- `python -B scripts/build_player_bundle.py --output-dir tmp/w34-player-source-candidate --allowlist-out tmp/w34-player-source-candidate.hygiene-allowlist.json`
  generated a 311-file source-delivery candidate.
- `python -B scripts/check_player_bundle_hygiene.py tmp/w34-player-source-candidate --allowlist tmp/w34-player-source-candidate.hygiene-allowlist.json`
  passed across 385 candidate members.
- Focused suspicious-token inventory for challenge terms, internal gates,
  release archives, and internal build-profile identifiers returned no matches
  in the generated candidate.
- `python -B scripts/check_player_package_runtime.py --output-dir tmp\w34-player-source-candidate --allowlist-out tmp\w34-player-source-candidate.hygiene-allowlist.json --go go --docker docker --database-url "postgres://sentinel:sentinel@localhost:55433/sentinel_aml?sslmode=disable" --base-url "http://127.0.0.1:18080"`
  passed; host wrapper elapsed time was 38.360 seconds and the script reported
  38.156 seconds.
- `/usr/bin/timeout 300 make wave33-gate` passed on the WSL GNU-timeout/make
  path. Host wrapper elapsed time was 130.900 seconds; the runner reported
  `wave33-gate: pass elapsed=130.421s`.
- `/usr/bin/timeout 300 make ad-stability-gate` passed on the WSL
  GNU-timeout/make path. Host wrapper elapsed time was 94.144 seconds; the
  runner reported `ad-stability-gate: pass elapsed=93.697s`.
- The final aggregate-generated player candidate scan passed across 385 members,
  its generated allowlist was `{"allow": []}`, and the focused leak-token
  inventory returned no matches.
- `python -B scripts/check_repository_submission_hygiene.py` passed after
  cleanup; no generated candidate or cache artifacts remain in `tmp/`.

## Tests

- `python -B -m unittest discover -s tests -p "test_player_bundle_build.py"` -
  exit 0, 12 tests in 1.090s.
- `python -B -m unittest discover -s tests -p "test_player_bundle_hygiene.py"` -
  exit 0, 18 tests in 0.244s.
- `python -B -m unittest discover -s tests -p "test_player_package_runtime.py"` -
  exit 0, 3 tests in 0.014s.
- `python -B -m unittest discover -s tests -p "test_runtime_smoke.py"` - exit
  0, 7 tests in 0.005s.
- `python -B -m unittest discover -s tests -p "test_docs_tree.py"` - exit 0,
  10 tests in 0.269s.
- `go test ./...` in `tmp/w34-player-source-candidate` passed, proving the
  staged source transform leaves candidate Go identifiers internally
  consistent.

## Allowed Exceptions

No W34 token exceptions are required for the player candidate. Before runtime
proof, the builder emits `PACKAGING_STATUS.json` with staged/not-ready status.
After `scripts/check_player_package_runtime.py` passes, the generated candidate
is stamped as source runtime-ready with a successful proof record.

## Invariants

- Organizer checker, sploits, fixes, vulnerable profiles, tests, and evidence
  remain in the organizer repository.
- Two checker flag stores, owner-view checker GET, CHECK/HAVOC coverage, five
  reference sploits, five reference fixes, vulnerable-profile coverage, and
  exploit-blocking fix evidence are preserved by the Wave 33 and A/D stability
  gates.
- No product runtime endpoints, debug/admin toggles, direct DB shortcuts,
  checker credentials, sample flags, or public flag fields were added.

## Risks

The source candidate is now runtime-proven, but no release archive, final
manifest, checksum, or image push is produced in Wave 34.
