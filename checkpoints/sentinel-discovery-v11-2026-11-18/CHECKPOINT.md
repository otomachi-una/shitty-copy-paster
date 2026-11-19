# Sentinel discovery v11 checkpoint

Captured 2026-11-18 before the repeatability check. Preserves the exact prompt script, source tree, all prompt turns, service map, three independent pass reports, final findings, local benchmark checklist, and sanitized network trace.

## Run design

- Provider: Qwen web chat, one fresh context.
- Four source parts, one service map, three audit passes, and one final findings-only reconciliation.
- Fast mode for source/map/entrypoint/sensitive-flow passes; Thinking mode for policy/provenance and final reconciliation.
- Maximum prompt message: 130,306 characters (Qwen limit: 131,072).
- Ground truth was kept out of all submitted prompts and used only after capture.
- Browser closed after capture.
- Python syntax compilation and prompt packing succeeded. No service tests were run.

## Observed result

The final report surfaced all five Sentinel benchmark vulnerabilities and distinguished the five key control failures: per-record graph ownership, private-note use in duplicate preview, redacted-event detail escalation, linked export scope context, and dossier coverage-policy enforcement. This is a single successful run; repeat before treating it as reliable.
