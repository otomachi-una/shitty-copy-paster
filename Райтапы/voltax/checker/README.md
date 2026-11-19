# VoltaX Exchange Checker Runtime

Deploy this package on the ForcAD checker host. It contains only the
VoltaX checker, checker Python requirements, and ForcAD-compatible
configuration.

It intentionally excludes sploits, fixes, writeups, validation
evidence, participant source, and organizer vault material.

## Install

```sh
python -m pip install -r voltax/requirements.txt
```

## ForcAD Contract

- `checker_type: pfr`
- checker path: `voltax/checker.py`
- places: 4
- standard Hackerdom-compatible actions:
  - `CHECK HOST`
  - `PUT HOST INCOMING_FLAG_ID FLAG PLACE`
  - `GET HOST PRIVATE_FLAG_ID FLAG PLACE`
- checker status is the process exit code
- PUT stdout is compact public attack-data JSON only
- PUT stderr is the private opaque `flag_id` only
- private checker state is never published to participants
- organizer-level `game.flag_lifetime` must be configured separately
  in the complete ForcAD event config; do not put `flag_lifetime` on
  the VoltaX task snippet

Set `VOLTAX_CHECKER_SECRET=<strong organizer secret>` in the checker
environment. For the production vulnerable competition environment,
set `VOLTAX_CHECKER_POLICY=competition`. Do not place the organizer
vault on this host unless the event operator explicitly approves that
larger trust boundary.
