# Wave 33 Binary String Hardening

## Summary

FH-03 reduces player-binary spoiler strings without changing service behavior,
routes, JSON keys, checker behavior, or intended vulnerable surfaces.

The player build continues to use:

```sh
go build -trimpath -ldflags "-s -w"
```

## Denied Binary Strings

The player disclosure scanner rejects direct defect/build-profile labels and
test-only marker strings in player binaries, including:

- `aml*_vulnerable`;
- build profile tags such as `case_match_preview`,
  `audit_detail_view`, `entity_review_summary`,
  `linked_case_export_detail`, and `network_room_detail`;
- internal side-view function/field markers such as
  `FindDuplicatePrivateNotesForPreview`, `LinkedPrivateNotes`,
  `DossierPrivateNote`, `ForeignPrivateNotes`, and related variants;
- package-hardening markers `sensitive_marker_value`,
  `private_service_marker`, `source_scope_materialized`, and
  `collaboration_context_detail`.

## Allowed Binary String Classes

Remaining strings are expected to be normal product/API/runtime material:

- Go runtime and build metadata, for example `runtime.`, `go1.`, `GODEBUG`,
  and panic text;
- product API and operational strings, for example `/api/`, `healthz`,
  `readyz`, `DATABASE_URL`, `duplicate`, `candidate`, `network_room`,
  `redaction_policy`, and `private_data_policy`;
- packaged runtime names such as `aml-api`, `aml-worker`, `aml-migrate`, and
  `sentinel_aml`.

The word `candidate` is allowed only as product duplicate-review vocabulary,
not package staging metadata.

## Verification

Run:

```sh
python -B scripts/check_ctf_disclosure_hygiene.py tmp/player-service-candidate --allowlist tmp/player-service-candidate.hygiene-allowlist.json
go tool nm tmp/player-service-candidate/bin/aml-api
strings tmp/player-service-candidate/bin/aml-api
```

The expected `go tool nm` result for stripped player binaries is no normal
symbol table. The strings scan must not show denied binary strings above.
