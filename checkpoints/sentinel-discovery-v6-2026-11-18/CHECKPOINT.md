# Sentinel discovery prompt v6 checkpoint

Captured 2026-11-18 before repeatability runs. This checkpoint preserves the exact audit script, service input tree, generated prompts, sanitized network trace, Qwen service map, findings-only response, and local benchmark checklist.

## Run design

- Provider: Qwen web chat, one fresh browser context.
- Messages: four source parts, one explicit service-map turn, one findings-only analysis turn.
- Maximum prompt message: 130,306 characters (Qwen limit: 131,072).
- The local ground-truth checklist is stored separately from the submitted prompt files.
- The browser was closed after capture.
- `manual_chat_contexts.py` passed `py_compile`; prompt packing completed. No service tests were run.

## Observed result

The response surfaced all five benchmark issue areas. AML-1 and AML-3 had precise root-cause descriptions. AML-2, AML-4, and AML-5 had the affected data paths but imprecise root-cause attribution. Treat this as a promising single run, not a repeatability result.

## Next experiment

Run the preserved v6 prompt twice more against the preserved source using fresh Qwen browser profiles. Do not modify the prompt between runs. Compare both issue-area recall and root-cause accuracy against `run/GROUND_TRUTH.md`; keep solver and patch generation out of these trials.
