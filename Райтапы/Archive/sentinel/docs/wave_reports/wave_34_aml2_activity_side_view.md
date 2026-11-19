# Wave 34 AML-2 Activity Side View

## Summary

Wave 34 turns AML-2 from a serializer-only owner timeline behavior into a real
related-entity activity side-view chain. The new route is
`GET /api/entities/{entity_hint}/activity`.

## Route Model

The route is authenticated and business-plausible: a requester may inspect
activity for an entity hint only after they own at least one customer with the
same normalized `entity_hint`. Unknown or unrelated entity hints fail closed.

The secure projection returns activity metadata, public case summary, object and
event types, and redacted sensitive field changes. The competition profile
selected by `audit_detail_view` / `aml2_vulnerable` keeps the same route and
authorization shape but incorrectly expands related `case_note.body` changes
into the raw `CaseNote.body` value.

## Evidence

- Negative: attacker `GET /api/cases/{victim_case}/notes` remains `404`.
- Negative: attacker `GET /api/cases/{victim_case}/timeline` remains `404`.
- Secure default: related entity activity exists but returns redacted
  `case_note.body` evidence and no raw note body.
- Competition profile: related entity activity exposes only the intended
  `case_note.body` change for related activity.
- Checker owner GET remains unchanged and still uses owner
  `GET /api/cases/{case_id}/notes`.

## Commands

```sh
go test ./internal/audit
go test ./internal/httpapi -run "Audit|AML2|Visibility"
go test -tags audit_detail_view ./internal/httpapi
python -B -m unittest discover -s tests -p "test_wave20_gate.py"
python -B -m unittest discover -s tests -p "test_wave25_gate.py"
python -B scripts/check_competition_matrix_gate.py
```

Live PostgreSQL hook:

```sh
SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://... go test ./internal/httpapi -run LivePostgresWave34AML2EntityActivitySideView
```

Without `SENTINEL_AML_INTEGRATION_DATABASE_URL`, the live hook skips and does
not count as full live acceptance.

## Anti-Goals

No direct DB path, debug/admin route, checker-private credential, cross-owner
timeline access, or cross-owner notes access was added. AML-2 remains a planned
side-view projection flaw, not a broad authorization bypass.
