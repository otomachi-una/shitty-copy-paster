# Sentinel AML — Workers and Async Flows

Wave 34 keeps risk scoring synchronous and in-process, and gives `aml-worker`
one deterministic runtime job: materialize network investigation rooms for
matching cases. EDD persistence and owner HTTP APIs remain owner-scoped and do
not add worker-side private-data reads.

## Current Behavior

The worker opens the normal application database and scans for cases with the
same normalized `entity_hint` and `typology_hint`. Groups with at least two
cases create or find one deterministic network room, attach all matching case
references, and add each owning analyst as a room participant. The scan is safe
to run repeatedly: uniqueness on room keys, room-case links, and participants
turns reruns into duplicate counters rather than new records.

The API process wires `internal/risk.Service` with the transaction and alert repositories. After a transaction is created, the service:

- reads the transaction through the owner-scoped transaction repository;
- computes a deterministic risk score;
- updates the server-owned `transactions.risk_score`;
- creates one alert when the score is suspicious;
- treats duplicate alert creation as a safe repeat run.

No external API, ML model, randomness, debug trigger, or direct database
shortcut is used. The long-running worker polls on a fixed interval and the
bounded smoke/runtime path uses `go run ./cmd/aml-worker --once` for one scan
and clean exit.

## Wave 05 EDD Worker Boundary

EDD records are created, read, and updated only through the owner-authenticated HTTP API and repository path. Workers do not inspect, copy, export, redact, score, delete, or publish `EDDRecord.confidential_comment` in Wave 05.

## Wave 08 Audit Worker Boundary

Wave 08 adds synchronous audit persistence primitives and in-process owner workflow instrumentation only. The `aml-worker` binary remains a placeholder and does not create, redact, replay, export, publish, or delete audit events.

Audit event creation is an in-process repository operation. HTTP owner workflows pass structured field changes to `internal/audit`, which redacts sensitive fields before `diff_json` is inserted. The owner case timeline reads stored audit events synchronously through an owner-scoped repository primitive. No queue, background timeline builder, audit fanout, public projection, AML-2 vulnerable timeline, or checker path is implemented in Wave 08.

## Wave 09 Graph Worker Boundary

Wave 09 adds `entity_graph_nodes`, `entity_graph_edges`, and synchronous `internal/graph` repository primitives only. The `aml-worker` binary remains a placeholder and does not populate, refresh, traverse, export, publish, or delete graph data.

The Wave 09 repository derives safe related-entity summaries at query time from existing normalized `entity_hint`, case public metadata, and EDD review status. There is no queue, graph builder job, background traversal, cache warmer, external enrichment source, AML-3 vulnerable graph projection, or checker path in W09-T01.

## Wave 10 Export And Network-Room Worker Boundary

Wave 10 export generation and network-room dossier construction are synchronous
repository/service primitives. Wave 34 adds only deterministic room
materialization to `aml-worker`; export generation, dossier rendering, graph
traversal, EDD processing, retention cleanup, and checker behavior remain
outside the worker.

W10-T03 network-room behavior is references-first. Rooms are created or found
deterministically from normalized entity and typology metadata, case links store
case IDs only, and safe dossiers are built from already-authorized public
summaries. Wave 34 makes this lifecycle automatic by scanning persisted cases;
the worker still does not copy note bodies, EDD confidential comments, audit
diffs, export payloads, checker-private state, or public attack data.

Wave 18 adds AML-5 only as a compile-time `aml5_vulnerable`/`network_room_detail`
dossier profile. Wave 34 supplies the real lifecycle that establishes matching
rooms and participant records; the tagged dossier leak is still presented only
through the normal network-room HTTP path after deterministic participation has
been established.

## Wave 04 Deterministic Risk Baseline

Architecture Decision Candidate: until a formal ADR replaces it, Wave 04 uses this deterministic formula:

```text
risk_score = f(amount_bucket, country, counterparty_fingerprint, typology_hint)
```

Inputs:

- `amount_bucket` from the validated transaction amount:
  - `small`: `< 1000.00`, weight 5;
  - `medium`: `1000.00` through `9999.99`, weight 20;
  - `large`: `10000.00` through `49999.99`, weight 45;
  - `very_large`: `>= 50000.00`, weight 65.
- `country`: static country weight of 20 for `IR`, `KP`, and `SY`; otherwise 0.
- `counterparty_fingerprint`: deterministic keyword weight of 20 for fingerprints containing `sanction`, `watchlist`, `shell`, or `mule`; otherwise `(rune sum % 3) * 5`.
- `typology_hint`: derived deterministically when absent:
  - `high-risk-country` when the country has a static country weight;
  - `counterparty-watchlist` when fingerprint keyword weight is present;
  - `large-value-transfer` for large and very-large amount buckets;
  - `standard-transaction` otherwise.

Typology weights:

- `high-risk-country`: 10;
- `counterparty-watchlist`: 20;
- `large-value-transfer`: 15;
- `standard-transaction`: 0;
- unknown internal typology: 5.

Scores are clamped to 100. `risk_score >= 70` creates an alert with:

```text
rule_code = DETERMINISTIC_RISK_THRESHOLD
typology_hint = derived typology
```

Alert creation is idempotent through the unique `(transaction_id, rule_code)` constraint and service-level duplicate handling.

## Wave 32 Runtime Smoke And Restart Safety

Wave 32 adds an archive-free runtime smoke command:

```sh
python -B scripts/runtime_smoke.py
```

The command assumes Docker Compose can start the repository PostgreSQL service
from `docker-compose.yml`, then applies migrations with `go run
./scripts/migrate`, starts the API locally, runs `go run ./cmd/aml-worker
--once` twice as a restart/idempotency check, and exercises representative
analyst workflows through normal HTTP APIs. Wave 34 extends the smoke workflow
with a related analyst case, runs `go run ./cmd/aml-worker --once` while the
API is live, and asserts that `GET /api/network/rooms` and
`GET /api/network/rooms/{room_id}/dossier` expose the deterministic room
without leaking owner private markers in the secure profile.

`cmd/aml-worker/main_test.go` pins the restart-safe scan behavior by invoking
`run(context.Background(), logger, scanner, interval, true)` twice and by
checking that a pre-cancelled context exits after the initial bounded scan.
`internal/networkroom` tests cover deterministic room grouping, case attachment,
participant creation, duplicate handling, and the rule that lifecycle queries
do not copy private note, EDD, audit, export, or checker material.

## Future Rules

Future workers must be deterministic, restart-safe, context-aware, and tested
against repeated execution. Queue selection and locking behavior remain open for
later waves.

Dedup triggers, graph refresh workers, EDD worker processing, checker behavior,
and reference fixes remain separate scope. The network-room lifecycle is active,
but room membership must not become a generic private-data read grant outside
the planned AML-5 dossier profile.
