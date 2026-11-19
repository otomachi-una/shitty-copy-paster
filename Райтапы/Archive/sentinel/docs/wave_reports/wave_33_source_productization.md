# Wave 33 Source Productization

## Summary

W33-T03 replaces obvious vulnerability/profile filenames and Go symbols in the
scoped source packages with product-neutral profile names while preserving the
organizer A/D evidence path. Behavior is unchanged: the same five intended
business-logic profiles remain available, default/fixed behavior remains
available, and existing organizer tags still compile as compatibility aliases.

No HTTP endpoints, checker flows, sploits, fixes, migrations, Docker runtime, or
business behavior changed in this task.

## Neutral Mapping

| Legacy organizer label | Product-neutral profile | Runtime/source surface |
| --- | --- | --- |
| AML-1 dedup vulnerable profile | `case_match_preview` | Duplicate case match preview code and tests |
| AML-2 audit vulnerable profile | `audit_detail_view` | Case audit detail code and tests |
| AML-3 graph vulnerable profile | `entity_review_summary` | Entity review EDD summary code and tests |
| AML-4 export vulnerable profile | `linked_case_export_detail` | Linked-case export detail code and tests |
| AML-5 network-room vulnerable profile | `network_room_detail` | Network room dossier detail code and tests |

## Renamed Source Surfaces

- `internal/httpapi/*_aml1_vulnerable.go` to
  `internal/httpapi/dedup_profile_case_match.go`.
- `internal/httpapi/*_aml2_vulnerable.go` to
  `internal/httpapi/audit_profile_detail.go`.
- `internal/httpapi/*_aml3_vulnerable.go` to
  `internal/httpapi/graph_profile_entity_review.go`.
- `internal/httpapi/*_aml4_vulnerable.go` to
  `internal/httpapi/export_profile_linked_case.go`.
- `internal/httpapi/*_aml5_vulnerable.go` to
  `internal/httpapi/network_room_profile_detail.go`.
- Default/fixed profile source filenames now use `*_profile_default.go` instead
  of `*_profile_secure.go`.
- `internal/graph/repository_aml3_vulnerable.go` to
  `internal/graph/repository_entity_review.go`.
- `internal/exporting/export_profile_aml4_vulnerable.go` to
  `internal/exporting/export_profile_linked_case.go`.
- `internal/networkroom/dossier_profile_aml5_vulnerable.go` to
  `internal/networkroom/dossier_profile_room_detail.go`.
- `internal/networkroom/repository_aml5_vulnerable.go` to
  `internal/networkroom/repository_room_detail.go`.

Representative symbol changes:

- `aml1VulnerableProfileEnabled` to `caseMatchPreviewProfileEnabled`.
- `aml2VulnerableProfileEnabled` to `auditDetailProfileEnabled`.
- `aml3VulnerableProfileEnabled` to `entityReviewSummaryProfileEnabled`.
- `aml4VulnerableProfileEnabled` to `linkedCaseExportProfileEnabled`.
- `aml5VulnerableProfileEnabled` to `networkRoomDetailProfileEnabled`.
- `VulnerableEDDSummary` to `ReviewEDDSummary`.
- `ListVulnerableEDDSummaries` to `ListReviewEDDSummaries`.
- `VulnerableCaseDossierInput` to `ExtendedCaseDossierInput`.
- `BuildVulnerableDossier` to `BuildExtendedDossier`.
- AML-5 runtime redaction policy string changed from
  `aml5_vulnerable_network_room_dossier` to
  `network_room_collaboration_detail`.

## Compatibility Exception

Legacy build tags such as `aml1_vulnerable` through `aml5_vulnerable` remain in
the scoped profile `//go:build` lines as organizer-only compatibility aliases.
This preserves existing sploit/fix/checker evidence until later Wave 33 work
migrates release gates, vulnerable-profile runners, and patch/test references
to the neutral profile tags.

Those legacy tags are not approved for player source packages. A future
sanitizing player-source builder must strip or exclude compatibility build
constraints before `player-hygiene-gate` can accept source distribution.

Organizer-only tests still contain AML labels and marker strings for evidence
readability. Tests remain excluded from player candidates by the packaging
boundary and the player hygiene scanner.

## Tests Run

- `gofmt -w` on renamed profile source and test files - exit 0.
- `go test -timeout 120s ./internal/httpapi ./internal/exporting ./internal/graph ./internal/networkroom` -
  exit 0.
- `go test -timeout 120s -tags aml1_vulnerable ./internal/httpapi` -
  exit 0.
- `go test -timeout 120s -tags aml2_vulnerable ./internal/httpapi` -
  exit 0.
- `go test -timeout 120s -tags aml3_vulnerable ./internal/httpapi ./internal/graph` -
  exit 0.
- `go test -timeout 120s -tags aml4_vulnerable ./internal/httpapi ./internal/exporting` -
  exit 0.
- `go test -timeout 120s -tags aml5_vulnerable ./internal/httpapi ./internal/networkroom` -
  exit 0.
- `go test -timeout 120s -tags case_match_preview ./internal/httpapi` -
  exit 0.
- `go test -timeout 120s -tags audit_detail_view ./internal/httpapi` -
  exit 0.
- `go test -timeout 120s -tags entity_review_summary ./internal/httpapi ./internal/graph` -
  exit 0.
- `go test -timeout 120s -tags linked_case_export_detail ./internal/httpapi ./internal/exporting` -
  exit 0.
- `go test -timeout 120s -tags network_room_detail ./internal/httpapi ./internal/networkroom` -
  exit 0.
- `python -B -m unittest discover -s tests -p "test_player_bundle_hygiene.py"` -
  exit 0, 12 tests.
- `python -B scripts/build_player_bundle.py --output-dir <temp-candidate>` plus
  `python -B scripts/check_player_bundle_hygiene.py <temp-candidate>` -
  exit 0; scanned 18 candidate members.

`make ad-stability-gate` could not be executed literally in this Windows shell
because `make` is not installed. Full aggregate validation should be rerun by
W33-T06 after all profile-name migrations and packaging-gate updates land. This
task ran the focused default, legacy-tag, neutral-tag, and player-hygiene checks
for the touched surfaces.

## CTF and Security Invariants

- Intended vulnerable behavior was not removed.
- Default/fixed behavior was not removed.
- Existing organizer `aml*_vulnerable` tag builds still pass, preserving the
  current checker/sploit/fix evidence chain.
- Neutral tag builds also pass, proving the new productized profile names are
  usable independently.
- No public HTTP endpoints, debug routes, admin helpers, DB access paths, public
  flag fields, or profile-selection endpoints were added.

## Risks

- Legacy `aml*_vulnerable` build tags remain as internal compatibility aliases.
  They are intentionally documented as organizer-only and must be removed or
  stripped from any future player source candidate.
- Organizer tests still carry AML labels for evidence clarity. The player
  bundle scanner already excludes tests from player candidates.
- Full `ad-stability-gate` remains pending in an environment with `make`
  available, or after W33-T06 migrates aggregate gates to the neutral names.

## Ready for Review

Yes, for scoped source-surface productization with documented internal
compatibility exceptions.
