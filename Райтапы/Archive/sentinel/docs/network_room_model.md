# Sentinel AML — Network Room Model

Wave 10 adds secure network-room persistence, safe dossier primitives, and the
W10-T04 authenticated network-room route surface. Wave 18 adds AML-5 only as a
compile-time `aml5_vulnerable` profile. The default network-room model remains
references-first and does not add checker behavior, public attack data, exploit
scripts, reference fixes, or default private-data access.

## Purpose

Network rooms group cases by deterministic entity-like and typology metadata so analysts can coordinate around related public risk signals. A room is a normal investigation workspace, not a flag endpoint and not a shortcut around owner authorization.

## Persistence Model

`network_rooms` stores room metadata:

- `room_key`
- `entity_hint`
- `typology_hint`
- `status`
- `public_summary`
- `public_risk_tags`
- creator and timestamps

`network_room_cases` stores case references only:

- `room_id`
- `case_id`
- `relation_type`
- added-by user and timestamp

`network_room_participants` stores participation metadata only:

- `room_id`
- `user_id`
- `participant_role`
- join timestamp

The schema must not copy private note bodies, EDD confidential comments, EDD narrative fields, raw audit diffs, value hashes, raw case blobs, checker-private state, public attack data, artificial flag fields, or debug/admin metadata.

## Runtime Lifecycle

Wave 34 makes room creation deterministic in real service execution. The
`aml-worker` process scans persisted cases through normal repositories and
groups candidates by:

```text
same normalized customer.entity_hint + same normalized case.typology_hint
```

A group becomes eligible when it contains at least two cases. For every
eligible group the worker:

- creates or finds the one room key for that entity/typology pair;
- attaches every matching case by ID with relation `typology_match`;
- adds each owning analyst as a participant with role `analyst`;
- records duplicate case links and duplicate participants as idempotent rerun
  counters instead of creating new rows.

The lifecycle is safe to run as a long-lived worker or as a bounded one-shot
scan:

```sh
go run ./cmd/aml-worker
go run ./cmd/aml-worker --once
```

No debug endpoint, admin route, direct DB trigger, random seed, external
enrichment API, or test-only room seed is required. The worker stores only room
metadata, case references, and participant metadata; dossier contents are still
computed by the normal network-room HTTP path.

## Safe Dossier

The W10-T04 safe dossier API may include:

- room summary metadata;
- entity and typology hints;
- public risk tags;
- participant and case counts;
- case IDs and customer IDs;
- own and foreign case public summaries;
- case status, risk score, typology hint, and timestamps;
- an explicit `private_data_omitted` marker.

Room participation does not grant private case-note, EDD, audit, export, or checker visibility. Foreign source cases may appear only as public case summaries and references.

## HTTP Surface

The secure route surface is intentionally narrow:

- `GET /api/network/rooms`
- `GET /api/network/rooms/{room_id}`
- `POST /api/network/rooms/{room_id}/join`
- `GET /api/network/rooms/{room_id}/dossier`

All four routes require bearer authentication. List, detail, and dossier reads are participant-scoped. Joining requires an authenticated user and an existing room. Dossier responses use explicit DTOs and the same public/redacted policy for own and foreign source cases.

## AML-5 Tagged Vulnerable Profile

AML-5 is the fifth planned vulnerable profile and is under review after
W18-T01/T02. It is selected only by the Go build tag `aml5_vulnerable`.

In the tagged profile, only
`GET /api/network/rooms/{room_id}/dossier` may expose bounded foreign
source-case private data after the normal clustering/materialization and
participant path. Wave 34 verifies this path with real room lifecycle rather
than seeded rooms. The intended tagged fields are:

- `foreign_private_notes`
- `foreign_edd_comments`

The default build must continue to use safe dossiers with references and public
case summaries only. Room participation must not be documented or treated as a
general grant to private notes, EDD narrative data, audit diffs, export data,
checker-private state, credentials, sessions, public attack data, raw rows,
debug/admin controls, or broad source-case blobs.

The reference exploit `sploits/sentinel_aml/aml_network_room.py` remains locked
until Wave 23 opens after Wave 18 acceptance. The reference fix remains locked
until Wave 28 after exploit evidence is captured.
