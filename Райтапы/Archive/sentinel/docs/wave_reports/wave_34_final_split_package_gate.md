# Wave 34 Final Split-Package Gate

Status: verified for orchestrator review.

## Summary

W34-T04 adds a final split-package gate that validates the player-service,
admin/checker, and organizer-internal evidence tracks without combining their
artifacts. The gate proves package candidates and internal A/D evidence before
any future release archive step.

## Gate Command

```sh
make final-split-package-gate
```

The review command is:

```sh
/usr/bin/timeout 300 make final-split-package-gate
```

Verified on 2026-09-08 from the WSL GNU-timeout/make review path:

- command: `/usr/bin/timeout 300 make final-split-package-gate`
- exit code: `0`
- host elapsed: `147.199s`
- runner elapsed: `146.706s`
- resolved tools: `python3`, `go.exe`, `docker.exe`
- player runtime proof used `postgres://sentinel:sentinel@localhost:55434/sentinel_aml?sslmode=disable`
  and `http://127.0.0.1:18081`

The runner reported `player-service`, `admin-checker`, and
`organizer-internal` as `pass`, with `final_archives_created: false`.

Status-freeze interpretation: "final split-package gate" means the final Wave
34 aggregate validation gate for split candidate tracks. It is not a final
package release, final archive issuance, manifest, checksum set, image push, or
final competition-readiness acceptance. The canonical boundary is
`docs/wave_reports/wave_34_status_freeze.md`.

## Artifact Tracks

- `player-service`: rebuilds the runtime-proven source candidate, runs offline
  vendored Go test/build, validates package Compose, runs PostgreSQL/migration
  API/worker smoke, then scans the candidate with player hygiene and
  `--require-runtime-ready`.
- `admin/checker`: rebuilds the operator candidate, verifies its exact
  allowlisted inventory, validates the copied ForcAD config, and rejects
  reference attack/fix material, profile-specific source, wave history, and
  sample secret values.
- `organizer-internal`: runs the archive-free A/D stability gate, archive
  hygiene, repository-submission hygiene, docs tree, and root ForcAD config.

## Boundary

The gate does not create final archives, player release archives, manifests,
checksums, or image pushes. Candidate directories are generated only under
ignored `tmp/` paths during the run and cleaned before archive hygiene.

## Required Evidence

The gate preserves all A/D evidence from `ad-stability-gate`: checker tests,
competition matrix validation, five sploit syntax checks, five fix patch
checks, vulnerable-profile tests, release-profile Go tests, Go vet/build,
docs-tree, and ForcAD config validation.

The nested organizer evidence phase passed in the final gate with
`ad-stability-gate: pass elapsed=90.291s`. The player source proof rebuilt a
311-file candidate, scanned 385 candidate members, ran candidate
`go test ./...`, ran candidate `go build ./cmd/aml-api ./cmd/aml-worker
./cmd/aml-migrate`, validated package Compose, applied 9 migrations, restarted
the worker twice, completed API health/workflow smoke, stamped runtime
readiness, and reran player hygiene with `--require-runtime-ready`.

The admin/checker candidate contained exactly 7 allowlisted files:
`PACKAGING_STATUS.json`, `README.md`, `config.yml`,
`config/operator.env.example`, `sentinel_aml/checker.py`,
`sentinel_aml/checker_lib.py`, and `sentinel_aml/requirements.txt`.

## Security Checks

Player hygiene must pass on the runtime-ready player candidate. Admin hygiene
must pass on the admin/checker candidate. Neither candidate may include the
other artifact class or organizer-only sploits, fixes, vulnerable-profile
source, tests, wave reports, debug helpers, sample secrets, final archives,
manifests, or checksums.
