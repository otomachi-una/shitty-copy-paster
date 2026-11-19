# W34-P03 Player Source Hygiene and Anti-Spoiler Scanner

## Summary

W34-P03 adds artifact-first hygiene checks for the canonical player source artifact:

```text
out/artifacts/sentinel-aml-player-source.tar.gz
```

The scanner inspects tar members and file contents from the artifact bytes, not from the repository working tree. It fails on organizer-only paths, generated/cache paths, spoiler tokens, comment leaks, build-tag leaks, and dual-policy source naming.

## Scanner Policy

Blocking path classes:

- `checkers/`, `sploits/`, `exploits/`, `fixes/`
- `docs/`, `validation/`, `out/`, `tmp/`, `.git/`
- `scripts/check_*`, `scripts/run_*`
- generated transfer/cache suffixes such as `.pyc`, `.pyo`, `.map`, `.tsbuildinfo`, `.tar`, `.tgz`, `.zip`
- frontend build/test output such as `frontend/node_modules/`, `frontend/dist/`, `frontend/e2e/`, `frontend/tests/`, `frontend/scripts/`

Blocking text classes:

- defect labels: `aml1` through `aml5`, and `AML-1` through `AML-5`
- attack-defense operational spoilers such as `exploit`, `sploit`, `checker`, `putflag`, `getflag`, `attack_info`, `public_attack_data`, `flag_store`
- profile or reference labels such as `secure_profile`, `vulnerable_profile`, `reference_fix`
- explicit leak markers such as `must_not_leak`, `leak_target`
- the word `flag`, unless a narrow allowlist entry explains why the occurrence is business/runtime-neutral

Blocking dual-policy classes:

- `*_secure.*`
- `*_vulnerable.*`
- `*_profile_*.*`
- `profile_*.*`
- `*_policy_*.*`
- `*_default.go` / `*_detail.go` source naming, including paired default/detail sources

The scanner also checks that Docker Compose builds from the player package source context, and that the Dockerfile builds the Go service and frontend from source rather than copying prebuilt binaries.

## Allowlists

The scanner records allowlisted findings in the JSON/CSV report with path, line, token, severity, and reason.

Approved narrow exceptions:

- `vendor/**`: third-party dependency vocabulary and build constraints are not Sentinel challenge metadata.
- `cmd/aml-api/main.go`, `cmd/aml-worker/main.go`: Go standard library `flag` package usage for runtime CLI options.
- `Makefile`, `Dockerfile`, `TROUBLESHOOTING.md`: `GOFLAGS` as operational build guidance.
- `internal/audit/repository.go`, `internal/exporting/redaction.go`, `internal/projection/contracts.go`: static redaction/projection labels that protect sensitive fields and do not include checker state, secret values, or reference evidence.

## Artifact Scan

Command:

```bash
python -B scripts/check_player_source_hygiene.py out/artifacts/sentinel-aml-player-source.tar.gz --json-report out/artifacts/player-source-hygiene-report.json --csv-report out/artifacts/player-source-hygiene-report.csv
```

Result:

```json
{
  "status": "pass",
  "file_count": 385,
  "hit_count": 1762,
  "blocking_hit_count": 0,
  "allowlisted_hit_count": 1762
}
```

Artifact SHA-256:

```text
c2c64d50075977bff48032d25c843e54172fdc97e7bc7468959426d031348f5c
```

Remaining risk score: low. The remaining hits are explicit, reviewable allowlist entries dominated by vendored third-party dependency vocabulary.

## Validation Commands

```bash
python -B -m unittest discover -s tests -p "test_player_source_hygiene.py"
python -B scripts/check_player_source_hygiene.py out/artifacts/sentinel-aml-player-source.tar.gz --json-report out/artifacts/player-source-hygiene-report.json --csv-report out/artifacts/player-source-hygiene-report.csv
python -B scripts/check_player_source_no_dual_policy.py out/artifacts/sentinel-aml-player-source.tar.gz
python -B scripts/check_player_source_manifest.py out/artifacts/sentinel-aml-player-source.tar.gz
```

All commands passed.

## CTF Invariants

The W34-P03 changes add scanners and tests only. They do not alter product behavior, checker behavior, sploits, reference fixes, migrations, or the intended competition behavior.

## Security Invariants

No debug/admin shortcut was added. No authorization path was changed. The scanner is designed to prevent secrets, checker state, organizer-only paths, reference evidence, and internal validation materials from entering the player source artifact.
