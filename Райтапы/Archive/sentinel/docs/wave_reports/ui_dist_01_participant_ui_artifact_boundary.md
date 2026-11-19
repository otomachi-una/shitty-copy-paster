# UI-DIST-01 Participant UI Artifact Boundary

Status: implementation ready for orchestrator review.

## Strategy

Participant-facing UI is distributed as production runtime files copied from
`frontend/dist` into the generated player candidate under `ui/`. It is not a
frontend source handoff. The internal frontend source package created by
`npm run package:source` remains organizer/developer material only.

The generated Compose template serves `ui/` through a static web container. The
same container proxies service requests to the API service, so the default
`ui/runtime-config.js` can remain credential-free and same-origin. Operators may
replace `ui/runtime-config.js` with an environment-specific value before serving
the static files.

## Boundary

The participant UI artifact must not contain frontend source, `frontend/tests`,
`frontend/e2e`, scanner scripts, Playwright configuration, generated reports,
source maps, browser profiles, temporary screenshots, local dumps, or agent
workflow hints.

`scripts/check_player_bundle_hygiene.py` scans the exact generated candidate
tree or archive. When `ui/` is present it requires `ui/index.html` and
`ui/runtime-config.js`, rejects source-map artifacts and source-map references,
and scans UI content for forbidden CTF/internal, development-test, scanner, and
agent workflow vocabulary.

## Validation

Focused validation commands:

```sh
npm --prefix frontend run security:scan:source
npm --prefix frontend run build
npm --prefix frontend run security:scan:dist
python -B scripts/build_player_bundle.py --output-dir tmp/ui-dist-player-candidate --allowlist-out tmp/ui-dist-player-candidate.hygiene-allowlist.json
python -B scripts/check_player_bundle_hygiene.py tmp/ui-dist-player-candidate --allowlist tmp/ui-dist-player-candidate.hygiene-allowlist.json
```

Local validation result:

| Check | Result | Evidence |
| --- | --- | --- |
| Python packaging script compile | PASS | `py_compile` passed for player bundle and hygiene scripts |
| Frontend typecheck | PASS | `npm run typecheck` |
| Frontend unit/component tests | PASS | 15 files, 107 tests |
| Frontend source scan | PASS | `UI player-facing source security scan passed` |
| Frontend production build | PASS | Vite built `index.html`, CSS, and JS runtime assets |
| Frontend dist scan | PASS | `UI player-facing dist security scan passed` |
| Player candidate build | PASS | generated 317 files; `frontend_ui.artifact_class=runtime-dist`, `delivery_path=ui/`, `file_count=4` |
| Participant UI artifact scan | PASS | `player-bundle-leak-scan` scanned 393 candidate members |
| Source-map absence | PASS | no `.map` files or `sourceMappingURL` references in `frontend/dist` or candidate `ui/` |
| Forbidden token scan | PASS | no CTF/internal, scanner, Playwright/Vitest, agent, DTO/projection/adapter/backend/API-contract tokens in candidate `ui/` |

Backend source, checker logic, sploit logic, reference fixes, and ForcAD
contracts are outside this change.
