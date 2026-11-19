# VoltaX Exchange Organizer Vault Runbook

This package is organizer-only. Do not distribute it to participants.
Deploy the separate checker-runtime package to ForcAD.

## Inputs

- extracted participant tree, for example `/srv/voltax-exchange-team`;
- running participant service URL, for example `http://localhost:9292`;
- organizer-controlled checker credential in `VOLTAX_CHECKER_SECRET`.

## 1. Inspect Package

```sh
cat MANIFEST.json
cat CHECKSUMS.sha256
```

## 2. Validate Checker Behavior

```sh
VOLTAX_CHECKER_SECRET=change-this-organizer-credential \
  ruby bin/validate-checker --policy competition http://localhost:9292
```

The helper runs `check`, `havoc`, and PUT/GET for places 1 through 4.

## 3. Prove PFR Public/Private Split

```sh
VOLTAX_CHECKER_SECRET=change-this-organizer-credential \
  ruby bin/validate-pfr-public-data --checker-root . --json evidence/pfr-public-private.json http://localhost:9292
```

The evidence file records public keys and SHA-256 hashes only. It does
not write raw flags, credentials, or private `flag_id` values.

## 4. Exploit-Positive Validation

Generate public attack data with the checker, then pass the JSON
public object to the matching sploit:

```sh
VOLTAX_CHECKER_SECRET=change-this-organizer-credential \
VOLTAX_CHECKER_POLICY=competition \
  python checkers/voltax/checker.py PUT http://localhost:9292 incoming-system-flag-id SAMPLE_PLACE_1_VALUE 1 \
    > attack-data.json 2> private-flag-id.txt

ruby bin/run-sploits EX-1 http://localhost:9292 attack-data.json
```

For EX-5, the participant `matching-engine` service must already be
running as part of the participant Compose stand.

## 5. Fix-Negative Validation

```sh
ruby bin/check-fixes /srv/voltax-exchange-team
ruby bin/validate-fix-matrix --participant-tree /srv/voltax-exchange-team
ruby bin/validate-fix-matrix --participant-tree /srv/voltax-exchange-team --fixed-live
```

## 6. Retention Smoke

```sh
W18C_SERVICE_ROOT=/srv/voltax-exchange-team \
W18C_ADMIN_ROOT="$PWD" \
W18C_ROUNDS=7 \
ruby bin/run-retention-soak
```

## 7. Cleanup

```sh
docker compose down --remove-orphans -v
```
