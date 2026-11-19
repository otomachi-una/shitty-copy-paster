# Wave 28 W28-F01 Handoff - AML-5 Network-Room Reference Fix Patch

## 1. Summary

W28-F01 corrects the missing final reference-fix artifact by adding
`fixes/sentinel_aml/aml_network_room.patch`. The patch is AML-5 scoped and keeps
network-room join, summary, and dossier behavior alive while removing the tagged
path that exposed foreign source-case private notes and EDD confidential
comments through participant-visible dossiers.

## 2. Implementation Details

- Added an AML-5 patch artifact targeting only tagged network-room vulnerable
  profile/proof files.
- The patch makes the AML-5 dossier route use safe public dossier projection
  semantics for participant-visible output.
- The tagged repository reader stops loading private source-case note bodies and
  EDD confidential comments into dossier inputs.
- The tagged dossier builder preserves public room/case references and marks
  private data omitted with `references_only` / `omitted` policy metadata.
- Embedded proof tests in the patch now assert that public room and case evidence
  remains present while `foreign_private_notes`, `foreign_edd_comments`, `body`,
  and `confidential_comment` are absent from fixed dossier output.

## 3. Files Changed

- `fixes/sentinel_aml/aml_network_room.patch`
- `fixes/sentinel_aml/README.md`
- `docs/wave_reports/wave_28_W28-F01_handoff.md`

## 4. Tests Added

- Patch-embedded AML-5 network-room repository proof showing the fixed tagged
  reader uses participant-scoped public dossier cases without private joins.
- Patch-embedded AML-5 dossier proof showing fixed output keeps public summary
  evidence and omits foreign note/EDD leak fields.
- Patch-embedded HTTP proof showing join/dossier functionality remains available
  and participant/outsider access boundaries remain closed.

## 5. Tests Run

| Command | Exit | Evidence |
| --- | ---: | --- |
| `git apply --check --whitespace=error fixes/sentinel_aml/aml_network_room.patch` | 0 | Patch applies cleanly. |
| Temporary patched copy: `go test -tags aml5_vulnerable ./internal/networkroom ./internal/httpapi` with `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off` and temp `GOCACHE`/`APPDATA` | 0 | `ok sentinel-aml/internal/networkroom`; `ok sentinel-aml/internal/httpapi`; fixed proof covers public dossier evidence and omission of foreign private note/EDD fields. |
| `python -B -m unittest discover -s tests -p "test_checker_*.py"` | 0 | 97 tests passed. |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...` | 0 | All Go packages passed; executed from PowerShell with temp `GOCACHE`/`APPDATA`. |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...` | 0 | No vet findings; executed from PowerShell with temp `GOCACHE`/`APPDATA`. |
| `python -B scripts/check_archive_hygiene.py` | 0 | Archive hygiene passed. |

## 6. Documentation Updated

`fixes/sentinel_aml/README.md` now documents AML-5 purpose, scope, expected
blocked exploit, and anti-coarse-fix warning.

## 7. CTF Invariants Checked

- Checker PUT/GET behavior was not edited.
- Public attack data schema was not edited.
- Network-room endpoints and dossier generation remain present in the patch.
- The exploit is blocked by removing sensitive projection/materialization, not
  by disabling network rooms.

## 8. Security Invariants Checked

- Fixed dossier output omits foreign `CaseNote.body`.
- Fixed dossier output omits foreign `EDDRecord.confidential_comment`.
- Patch tests reject raw audit diff/hash/session/checker-private/raw DB markers.
- No debug/admin/direct DB shortcut is introduced by the final fixed path.

## 9. Self-Review

The change is intentionally limited to the AML-5 reference fix artifact and fix
README documentation. It does not alter working-tree product source, checker
logic, sploits, public attack data, migrations, deployment files, or AML-1
through AML-4 patch semantics. The patch includes behavioral proof changes
inside the artifact so reviewers can apply it and observe fixed AML-5 behavior.

## 10. Risks / Open Questions

- Full Wave 28 gate and matrix status are outside W28-F01 scope; this handoff
  covers the missing AML-5 patch artifact and required component validators.
  W28-F02 owns the Wave 28 gate and final fix-cell matrix alignment.
- The working tree is an extracted archive without `.git`; `git status` is not
  available, but `git apply --check` is available and passed.

## 11. Ready for Orchestrator Review

yes.
