# VoltaX Exchange Organizer Vault

This package is organizer-only. Keep it off participant hosts and off
the checker runtime host unless the operator explicitly accepts that
deployment boundary.

It contains reference sploits, participant-targeted fixes, checker
tests, validation helpers, and runbooks. The deployable ForcAD checker
package is the separate `voltax-exchange-checker-runtime` archive.

## Quick Commands

```sh
python -B -c "import pathlib; [compile(p.read_text(), str(p), 'exec') for p in pathlib.Path('.').glob('**/*.py') if '__pycache__' not in p.parts]"
ruby bin/validate-checker --policy competition http://localhost:9292
ruby bin/validate-pfr-public-data --checker-root . --json evidence/pfr-public-private.json http://localhost:9292
ruby bin/check-fixes /path/to/voltax-exchange-team
ruby bin/validate-fix-matrix --participant-tree /path/to/voltax-exchange-team
ruby bin/run-sploits --list
```

See `pre_event_validation_runbook.md` and
`pfr_public_private_runbook.md` for the full operator flow.
