# W24-T03 Handoff - AML-1 Exploit-Blocked and Anti-Coarse-Fix Evidence

## 1. Summary

Strengthened Wave 24 AML-1 evidence so the reference fix is not accepted merely
for hiding data. The Wave 24 tests now prove the accepted AML-1 exploit still
succeeds on the vulnerable fixture, fails safely on fixed public merge-preview
output, and that coarse or non-behavioral patches are rejected.

## 2. Implementation Details

- Reused the accepted Wave 19 AML-1 exploit module and fake service fixture from
  `tests/test_wave19_gate.py` without modifying
  `sploits/sentinel_aml/aml_dedup_preview.py`.
- Added a vulnerable-fixture proof that `aml_dedup_preview.py` extracts a flag
  when `candidate.private_notes[].body` is present.
- Added a fixed-output proof that the same exploit exits non-zero with
  `private_notes leak is absent` when merge-preview returns only public fields.
- Added negative gate tests for patches that remove merge-preview, disable
  dedup, change only docs, or change only gate constants.
- Extended `scripts/check_wave24_gate.py` documentation checks to recognize this
  W24-T03 handoff when present.

## 3. Files Changed

- `scripts/check_wave24_gate.py`
- `tests/test_wave24_gate.py`
- `docs/wave_reports/wave_24_W24-T03_handoff.md`

## 4. Tests Added

- `test_patch_blocks_leak_rejects_dedup_disablement`
- `test_patch_scope_rejects_docs_only_fix`
- `test_patch_scope_rejects_gate_constant_only_fix`
- `test_aml1_exploit_succeeds_on_vulnerable_fixture`
- `test_aml1_exploit_fails_safely_on_fixed_public_output`

## 5. Tests Run

| Command | Result |
| --- | --- |
| `python -B scripts\check_wave24_gate.py` | exit 0; status `pass` |
| `python -B scripts\check_competition_matrix_gate.py` | exit 0; status `pass` |
| `python -B -m unittest discover -s tests -p "test_wave24_gate.py"` | exit 0; 15 tests passed |
| `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` | exit 0; 28 tests passed |
| `python -B -m unittest discover -s tests -p "test_checker_*.py"` | exit 0; 97 tests passed |
| no-repo-cache `python -B -m py_compile` for all five exploits | exit 0 |
| release/offline `go test ./...` | exit 0 |
| release/offline `go vet ./...` | exit 0 |
| `python -B scripts\check_docs_tree.py` | exit 0; status `pass` |
| `python -B scripts\validate_forcad_config.py` | exit 0 |
| `python -B scripts\check_archive_hygiene.py` | exit 0; status `pass` |
| `make wave24-gate` | not runnable in this Windows shell; `make` is not installed in PATH |

## 6. Documentation Updated

This handoff records the W24-T03 exploit-blocked and anti-coarse-fix evidence.

## 7. CTF Invariants Checked

- Exploit evidence uses only public attack data:
  `service`, `store`, `case_id`, and `dedup_hint`.
- CHECK/HAVOC dedup remains meaningful because duplicate listing and
  merge-preview paths are still required.
- No checker DB shortcut is introduced.

## 8. Security Invariants Checked

- Fixed merge-preview output omits `candidate.private_notes`.
- The fixed-output exploit proof does not expose alternate flag fields, raw JSON
  note bodies, or nested note containers.
- Coarse patches that remove merge-preview or disable dedup are rejected.
- Docs-only and gate-constant-only patches are rejected as non-behavioral.

## 9. Self-Review

The change is evidence-only. It does not alter production Go source, exploit
code, checker code, migrations, deploy config, or non-AML-1 fix artifacts.

## 10. Risks / Open Questions

- The exploit-blocked proof uses the existing fake-service harness rather than a
  live patched Docker service.
- `make wave24-gate` depends on `make` availability in the local shell.

## 11. Ready for Orchestrator Review

Yes.
