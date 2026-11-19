# Sentinel AML UI Validation and Handoff

Every UI wave must report exactly what was verified. Do not claim browser, privacy, security, responsive, or build success for a command or viewport that was not run.

## Clean frontend gate

From `frontend/`:

```bash
npm ci
npx playwright install chromium
npm run typecheck
npm test
npm run security:scan
npm run build
npm run security:scan:dist
npx playwright test
```

`npm run verify` is a useful aggregate for typecheck, unit tests, source scan, build, and dist scan, but the clean handoff should still call out `npm ci`, browser install, and Playwright separately.

## Security gate

The required player-facing chain is:

```bash
npm run security:scan
npm run build
npm run security:scan:dist
```

The source scan checks frontend source/config/public files. The dist scan checks production JS/CSS/HTML and rejects production source map artifacts.

## Browser QA gate

The Playwright suite runs desktop and mobile projects:

- desktop: approximately 1440 px wide;
- mobile: approximately 390 px wide.

Required browser coverage includes:

- register/login and logout;
- alert queue and alert detail;
- claim/triage/create-case where the current API supports it;
- case private note read/write;
- customer and owner EDD;
- graph/network views;
- session isolation across two analysts;
- unauthorized redirect;
- safe `403`, `404`, session expiry, loading, empty, and error states;
- no horizontal page overflow on critical routes;
- keyboard focus and core form usability.

### Error-state browser matrix

The frontend error-state matrix is covered by `frontend/e2e/error-state-matrix.spec.ts` with deterministic Playwright route interception, not backend fixtures:

| State | Screen | Expected UI | Test |
| --- | --- | --- | --- |
| `401` | Case workspace followed by alert queue refresh | Session and query cache clear, login/session-expired flow appears, prior owner note is absent before and after another analyst opens the same case route. | `401 clears the session, removes private data from screen, and recovers through login` |
| `403` | Network rooms | Safe `Access denied` message, retry recovery, no raw payload text. | `403 renders access denied without raw payload and keeps recovery controls` |
| `404` | Missing customer | Safe resource-unavailable state with return-to-queue recovery, no raw server code. | `404 renders safe unavailable state with workspace recovery` |
| `409` | Alert detail case creation | Product conflict copy, case summary input preserved, refresh action available, no raw conflict JSON. | `409 explains case conflict, preserves entered summary, and offers refresh recovery` |
| `422` | Alert detail case creation | Safe validation copy, field input preserved, no raw backend JSON or `<pre>` payload rendering. | `422 renders validation-safe copy, preserves field input, and avoids backend JSON` |
| `500` | Alert queue | Neutral service error, retry recovery, no stack trace or backend package names. | `500 renders neutral service error without stack traces or backend packages` |
| Network failure | Alert queue and alert triage | Recoverable connectivity state with safe retry for read; write conflict is not automatically repeated without an explicit user action. | `network failure renders recoverable connectivity state and does not auto-repeat writes` |

Manual visual inspection may still be required for large visual changes. The automated smoke suite is not a substitute for reviewing material layout changes in the rendered browser.

## Backend gate

UI-only waves do not modify backend source. If backend files are untouched, report backend changes as `none`/`NO` and do not run broad Go gates unless needed for a specifically suspected integration issue.

If a backend exception is explicitly authorized, run nearest backend tests first and then the current aggregate/task-specific gate identified by `docs/source_of_truth_map.md`.

## Artifact hygiene

Source handoff must not include:

- `frontend/node_modules`;
- `frontend/dist`;
- `frontend/test-results`, `frontend/playwright-report`, or `frontend/blob-report`;
- TypeScript `.tsbuildinfo`;
- caches, browser downloads, generated screenshots, or temporary visual QA artifacts unless intentionally retained as evidence and documented.

The repository root `.gitignore` must cover generated frontend outputs.

Frontend source handoff uses an explicit allowlist package command from `frontend/`:

```bash
npm run package:source
npm run package:source:scan
```

`npm run package:source` creates `frontend-source.tar.gz` and immediately scans the archive entries. `npm run package:source:scan` re-scans an existing archive. The scanner validates the package artifact itself rather than the developer workspace, so a local `node_modules` or freshly built `dist` can exist without being included in source handoff. Runtime `dist` must be generated separately from a clean install/build.

## Handoff format

End each UI wave with:

1. Summary.
2. Files changed.
3. Architecture before/after when refactoring occurred.
4. Implemented flows.
5. Deferred/conditional flows.
6. Backend changes: `none` unless explicitly authorized.
7. Backend contract requests created/updated.
8. Security/visibility review.
9. Commands and PASS/FAIL/SKIPPED results.
10. Browser QA and viewport sizes.
11. Artifact hygiene result.
12. Known risks.
13. Readiness recommendation.
