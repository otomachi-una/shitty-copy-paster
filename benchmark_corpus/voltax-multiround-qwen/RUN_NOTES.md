# VoltaX multi-round audit benchmark

Task source: `services/voltax-exchange` (94 collected files). The organizer writeup was kept out of the prompts.

Model: Qwen3.8-Max. The run used two rounds. Each round started a fresh Chromium process with a temporary profile that was deleted after the response. The prior audit report was supplied as `seed-findings.json`. The seed had four confirmed findings and one RFQ workup lead marked `needs-context`.

Round 1 took 181 seconds. It retained the four confirmed findings and promoted F5, the RFQ workup exposure, to confirmed. The evidence traced `GET /api/rfq/:rfq_id/workup` through the `rfq_quote` capability check to `workup_terms` containing the owner’s `delivery_terms`.

Round 2 took 185 seconds and returned the same five confirmed findings. Against the five findings in the organizer writeup, the report moved from four confirmed plus one unresolved lead to five confirmed. The RFQ issue was already present as an unresolved lead in the seed, so this run demonstrates resolving a lead, not discovering a vulnerability absent from the initial report. No extra findings remained in the final report after comparison with the writeup.

Both rounds required the operator to solve Qwen’s CAPTCHA. See each `round-XX/review.json` and `round-XX/QWEN_FINDINGS_qwen-1.md` for the saved result.
