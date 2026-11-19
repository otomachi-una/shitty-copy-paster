# ForcAD PFR Public/Private Boundary

VoltaX uses `checker_type: pfr`. Checker status is determined by the
process exit code. On successful PUT:

```sh
stdout = {"place":1,"store":"order_note",...}
stderr = <opaque-private-flag-id>
exit code = 101
```

ForcAD must store stderr privately as `flag_id` and expose only stdout
through public attack data. The public object is sufficient for
reference attacks and must not contain credentials, flags, `flag_id`,
checker credentials, or private service state. There is no `OK ` prefix
and no `{"flag_id":...,"public":...}` wrapper in stdout.

## Live Proof

```sh
VOLTAX_CHECKER_SECRET=change-this-organizer-credential \
  ruby bin/validate-pfr-public-data --checker-root . --json evidence/pfr-public-private.json http://localhost:9292
```

The harness runs PUT/GET for places 1 through 4, validates that the
public object omits forbidden keys and raw target values, probes
`/api/client/attack_data`, and writes sanitized evidence.

## Simulation When Event ForcAD Is Not Available

```sh
ruby bin/validate-pfr-public-data --simulate --json evidence/pfr-simulated.json
```

Simulation verifies the expected stdout/private/public split but does
not replace final event-environment validation on the real ForcAD
deployment.
