# Sentinel AML - Open Questions

Architecture contract changes require an ADR or explicit orchestrator instruction. Historical early-wave questions about product schemas, database foundation, auth/session, checker place state, CHECK/HAVOC, planned vulnerability sequencing, reference exploits, reference fixes, and runtime A/D stability are resolved or frozen by the current source-of-truth map and roadmap.

## Current frontend/productization questions

- UI-BCR-001: should `duplicate_case` conflict responses expose an owner-scoped existing-case locator, or should the product keep the current safe refresh-only recovery?
- UI-BCR-002: should Sentinel add a dedicated owner-scoped customer activity endpoint, or should customer pages continue to rely on case timeline and related entity context only?
- Should final player/admin packaging include frontend source, a prebuilt static bundle, or a service/image artifact? This remains outside frontend ownership and belongs to later packaging acceptance.
- Should dependency audit findings reported by npm be addressed through targeted package upgrades, broader dependency refresh, or accepted risk? This requires a dependency/security maintenance decision, not a UI-only force fix.

## Current non-questions

- Backend source remains outside frontend ownership for UI correction waves.
- The frontend must not invent global customer, case, export, or graph collection endpoints.
- Owner-private case notes and EDD confidential comments remain owner-only UI content and are not side-view data.
- Frontend final readiness can be recommended only after the current clean frontend gate and browser smoke suite pass.
