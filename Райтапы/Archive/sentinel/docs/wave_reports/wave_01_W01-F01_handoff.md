1. Summary.

Restored the exact canonical Sentinel AML documentation tree, quarantined foreign legacy exchange material, tightened docs-tree validation to require pass status, and preserved Wave 01's no-product-behavior boundary.

2. Implementation Details.

- Added canonical Sentinel AML source-of-truth docs at the exact paths required by W01-F01.
- Quarantined foreign legacy exchange documents under `docs/archive/foreign_voltax/` with an explicit non-authoritative archive note.
- Recreated `docs/decisions/` as an empty Sentinel AML ADR area with a README.
- Added canonical Wave 01 prompt/fix prompt pool docs.
- Updated `docs/agent_packets/README.md` to point to `docs/wave_01_prompt_pool.md`, `docs/wave_01_fix_prompt_pool.md`, and future `docs/wave_02_prompt_pool.md`.
- Updated `scripts/check_docs_tree.py` to require exact Sentinel AML canonical paths, fail on active suffixed filenames, and fail on active foreign legacy content markers outside the archive and review/history artifacts.
- Updated `tests/test_docs_tree.py` to require docs-tree status `pass`.
- Updated the Wave 01 validation summary to `pass`.

3. Files Changed / Deleted / Quarantined.

- Created/updated canonical docs: `docs/00_project_overview.md`, `docs/01_ctf_contract.md`, `docs/02_domain_model.md`, `docs/03_api_contract.md`, `docs/04_database_model.md`, `docs/05_authentication_authorization.md`, `docs/06_visibility_and_projections.md`, `docs/07_flag_stores.md`, `docs/08_checker_design.md`, `docs/09_vulnerability_matrix.md`, `docs/10_workers_and_async_flows.md`, `docs/11_deployment.md`, `docs/12_testing_strategy.md`, `docs/13_roadmap.md`, `docs/15_risk_register.md`, `docs/source_of_truth_map.md`, `docs/definition_of_done.md`, `docs/open_questions.md`, `docs/aml_investigation_flows.md`, `docs/audit_export_graph_invariants.md`, `docs/network_room_model.md`, `docs/waves.md`, `docs/README.md`, `docs/wave_01_prompt_pool.md`, and `docs/wave_01_fix_prompt_pool.md`.
- Updated validation/docs files: `scripts/check_docs_tree.py`, `tests/test_docs_tree.py`, `docs/agent_packets/README.md`, `docs/wave_reports/wave_01_validation_summary.md`, `docs/wave_reports/wave_01_W01-F01_handoff.md`, and `docs/14_agent_execution_log.md`.
- Quarantined foreign legacy material under `docs/archive/foreign_voltax/`, including suffixed canonical-document candidates, old exchange-specific docs, old source material, old decision records, old agent packets, old manifest files, and the legacy wave0 report.
- No product, API, DB, checker, sploit, or config files were modified.

4. Tests Added.

- Updated docs-tree tests to require overall `pass` status.
- Updated docs-tree tests to require exact canonical Sentinel AML document presence.
- Updated docs-tree tests to assert no active legacy filenames or content markers remain outside ignored archive/review/history areas.

5. Tests Run.

- `python3 -B scripts/check_docs_tree.py` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python3 -B -m unittest discover -s tests -p "test_docs_tree.py"` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python3 -B -m unittest discover -s tests -p "test_*.py"` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python --version` reported Python 3.11.6.
- `python -B scripts/check_docs_tree.py` completed successfully and reported overall status `pass`.
- `python -B -m unittest discover -s tests -p "test_docs_tree.py"` completed successfully.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 13 tests.
- `python -B scripts/check_wave01_scope.py` completed successfully and reported overall status `pass`.
- `go test ./...` completed successfully.
- `go vet ./...` completed successfully.

6. Documentation Updated.

- Restored the canonical Sentinel AML docs tree.
- Updated `docs/agent_packets/README.md`.
- Updated `docs/wave_reports/wave_01_validation_summary.md`.
- Added this W01-F01 handoff report.
- Updated `docs/14_agent_execution_log.md` with the W01-F01 fix entry.

7. CTF Invariants Checked.

- Sentinel AML remains the only active service scope.
- ForcAD contract remains `checker_type: pfr`, `places: 2`, `puts: 2`, `gets: 2`.
- No checker uses DB, debug, or admin paths.
- No planned vulnerability or exploit code was introduced.
- No artificial flag fields were introduced.

8. Security Invariants Checked.

- No sensitive field exposure was added.
- No DB model serialization was introduced.
- No debug or backdoor endpoint was added.
- Visibility and projection requirements remain in canonical Sentinel AML docs only.

9. Self-Review.

- Summary: The cleanup resolves W01-T03's pending docs-tree gate by restoring exact Sentinel AML canonical docs and quarantining foreign legacy material.
- Files changed/deleted/quarantined: Active docs were canonicalized; foreign legacy files were moved under `docs/archive/foreign_voltax/`; no implementation files outside the allowed scope were changed.
- Tests added: Docs-tree tests now assert pass status and clean active docs.
- Tests run: Required `python3` commands were attempted and blocked by the host alias; equivalent Python 3.11 `python` commands, Wave 01 scope validation, Go tests, and Go vet completed successfully.
- Architecture contracts satisfied: Source-of-truth map is restored, execution log remains operational history, wave reports remain review artifacts, and decisions remain ADR-scoped.
- CTF invariants checked: No checker lifecycle, attack data, direct DB checker path, vulnerability, exploit, or artificial flag field was added.
- Security invariants checked: No sensitive exposure, DB serialization, debug route, or backdoor was added.
- Known gaps: Future `docs/wave_02_prompt_pool.md` is referenced as a future file but not created by Wave 01.
- Risks: Canonical docs are intentionally concise because this task did not receive a full Sentinel AML architecture packet beyond Wave 01 contracts.
- Deviations from plan: Quarantine was chosen over deletion to preserve provenance.
- Intentionally excluded work: API schemas, database migrations, auth/session logic, checker PUT/GET, vulnerability definitions, exploits, reference fixes, and ADR decisions.

10. Risks / Open Questions.

- Later waves should expand the concise canonical Sentinel AML docs only from approved packets or ADRs.
- `docs/wave_02_prompt_pool.md` remains future work.

11. Ready for Orchestrator Review: yes/no.

yes
