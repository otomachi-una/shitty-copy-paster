1. Summary.

Aligned the ForcAD config shape, validator, tests, and reference exploit placeholder documentation with the Sentinel AML architecture-source list-of-task format and five planned future exploit filenames.

2. Implementation Details.

- Updated `config.yml` from a `tasks.sentinel_aml` mapping to a `tasks` list containing `name: sentinel_aml`.
- Updated `scripts/validate_forcad_config.py` to require the source-aligned task-list shape and reject the old mapping shape.
- Updated `tests/test_forcad_layout.py` to assert task `name`, checker path, checker type, timeout, places, puts, gets, and mapping-shape rejection.
- Updated `sploits/sentinel_aml/README.md` to list exactly the five planned future exploit script names: `aml_dedup_preview.py`, `aml_audit_timeline.py`, `aml_related_graph.py`, `aml_export_redaction.py`, and `aml_network_room.py`.
- Updated `scripts/check_wave01_scope.py` and `tests/test_wave01_scope.py` to require the F01/F02 handoff reports and validate the future exploit README contract while still forbidding actual exploit scripts.
- Updated `checkers/sentinel_aml/README.md` with the source-aligned config wording.

3. Files Changed.

- `config.yml`
- `scripts/validate_forcad_config.py`
- `tests/test_forcad_layout.py`
- `scripts/check_wave01_scope.py`
- `tests/test_wave01_scope.py`
- `sploits/sentinel_aml/README.md`
- `checkers/sentinel_aml/README.md`
- `docs/wave_reports/wave_01_W01-F02_handoff.md`
- `docs/14_agent_execution_log.md`

4. Tests Added.

- Added config-shape regression coverage that rejects the old mapping form.
- Added assertion that `name: sentinel_aml` is present in the parsed task object.
- Added sploit README contract coverage for the five planned future exploit filenames.
- Added negative coverage ensuring generic two-store placeholder names are absent from the sploit README.
- Added Wave 01 scope coverage for the future exploit README contract and W01-F01/W01-F02 handoff reports.

5. Tests Run.

- `python3 -B scripts/validate_forcad_config.py` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python3 -B scripts/check_wave01_scope.py` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python3 -B -m unittest discover -s tests -p "test_forcad_layout.py"` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python3 -B -m unittest discover -s tests -p "test_wave01_scope.py"` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python3 -B -m unittest discover -s tests -p "test_*.py"` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python --version` reported Python 3.11.6.
- `python -B scripts/validate_forcad_config.py` completed successfully.
- `python -B scripts/check_wave01_scope.py` completed successfully and reported overall status `pass`.
- `python -B -m unittest discover -s tests -p "test_forcad_layout.py"` completed successfully with 7 tests.
- `python -B -m unittest discover -s tests -p "test_wave01_scope.py"` completed successfully with 4 tests.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 15 tests.
- `go test ./...` completed successfully.
- `go vet ./...` completed successfully.

6. Documentation Updated.

- Updated `sploits/sentinel_aml/README.md`.
- Updated `checkers/sentinel_aml/README.md`.
- Added this W01-F02 handoff report.
- Updated `docs/14_agent_execution_log.md` with the W01-F02 fix entry.

7. CTF Invariants Checked.

- `checker_type: pfr` remains set.
- `places: 2`, `puts: 2`, `gets: 2`, and `checker_timeout: 30` remain set.
- Checker path remains `sentinel_aml/checker.py`.
- Checker and sploit directories remain separate.
- No real exploit or checker behavior was added in Wave 01.

8. Security Invariants Checked.

- No direct DB checker dependency was added.
- No hidden debug or admin paths were added.
- No hard-coded credentials were added.
- No sensitive fields or artificial flag fields were added.

9. Self-Review.

- Summary: The ForcAD config and placeholder exploit docs now match the source-aligned Sentinel AML shape and naming contract.
- Files changed: Limited to the W01-F02 allowed file scope.
- Tests added: Focused config-shape, README contract, and Wave 01 scope assertions.
- Tests run: Required `python3` commands were attempted and blocked by the host alias; equivalent Python 3.11 `python` commands, Go tests, and Go vet completed successfully.
- Architecture contracts satisfied: Source-aligned task-list config, two-place PFR values, checker path, and five future exploit names are enforced.
- CTF invariants checked: No checker lifecycle, exploit script, vulnerability, reference fix, direct DB path, or hidden debug path was introduced.
- Security invariants checked: No credentials, sensitive fields, artificial flag fields, DB shortcut, or backdoor behavior was added.
- Known gaps: Real checker and exploit behavior remain intentionally absent.
- Risks: Existing canonical docs may need a later update to mention the five planned exploit filenames, but W01-F02 file scope did not include those docs.
- Deviations from plan: None.
- Intentionally excluded work: Checker CHECK/PUT/GET, exploit scripts, product APIs, database migrations, vulnerabilities, reference fixes, and debug/admin/backdoor endpoints.

10. Risks / Open Questions.

- Future vulnerability waves must define and implement the five planned exploit paths without adding scripts in Wave 01.
- A later docs wave may choose to mirror the five planned filenames into broader canonical docs if desired.

11. Ready for Orchestrator Review: yes/no.

yes
