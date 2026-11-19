# Sentinel AML - Attack-Defense / ForcAD Contract

Sentinel AML integrates with ForcAD as a Hackerdom-compatible Attack-Defense service.

## ForcAD Settings

The repository-local `config.yml` must define:

```yaml
tasks:
  - name: sentinel_aml
    checker: sentinel_aml/checker.py
    checker_type: pfr
    checker_timeout: 30
    places: 2
    puts: 2
    gets: 2
```

## Places

- Place 1: `CaseNote.body` owner workflow, implemented for Wave 11 PUT/GET
  through normal authenticated business APIs.
- Place 2: `EDDRecord.confidential_comment` owner workflow, implemented for
  Wave 12 PUT/GET through normal authenticated EDD business APIs.

## Wave 12 Checker Boundary

AD-C0 review status: accepted. Both checker places are active and the checker
flag-store contract is closed for Wave 12.

The checker supports:

- `CHECK` as a shallow health placeholder using `GET /healthz`.
- Place 1 PUT/GET for `CaseNote.body`.
- Place 2 PUT/GET for `EDDRecord.confidential_comment`.
- Fail-closed behavior for unknown places.

Checker flows must use normal business APIs. They must not use hidden APIs,
direct database access, debug routes, admin routes, or credential-bearing
public attack data.

Historical Wave 11 boundary: place 2 remained deferred until Wave 12 and
fail-closed in the checker.

## Place 1 PFR Data

Private `flag_id` is an integrity-protected checker state envelope. Its payload
contains only the recovery data needed by GET: service/store/place identifiers,
checker-owned username/password/token, customer/case/note IDs, public hints, and
the deterministic idempotency key. The envelope MAC is HMAC-SHA256 over
canonical payload JSON using the checker secret.

Public attack data for place 1 contains only:

- `service`
- `case_ref`
- `case_id`
- `customer_ref`
- `customer_id`
- `entity_ref`
- `party_ref`
- `matching_reference`

Public attack data must not contain credentials, bearer/session tokens, raw
flags, checker secrets, password hashes, session hashes, store labels, direct
`dedup_hint` / `typology_hint` keys, or private checker state.

## Place 2 PFR Data

Private `flag_id` for place 2 uses the same integrity-protected checker state
envelope pattern. Its payload contains service/store/place identifiers,
checker-owned username/password/token recovery data, the owner customer ID, the
EDD record ID, non-secret entity and typology hints, and the deterministic
idempotency key. The envelope MAC is HMAC-SHA256 over canonical payload JSON
using the checker secret.

Public attack data for place 2 contains only:

- `service`
- `customer_ref`
- `customer_id`
- `entity_ref`
- `party_ref`

Public attack data must not contain credentials, bearer/session tokens, raw
flags, checker secrets, password hashes, session hashes, store labels, direct
`typology_hint` keys, private checker state, or `confidential_comment`. Place 2
GET must read `EDDRecord.confidential_comment` only through the owner EDD view
and must not use graph, audit, export, network-room, dedup, or other side
views.
