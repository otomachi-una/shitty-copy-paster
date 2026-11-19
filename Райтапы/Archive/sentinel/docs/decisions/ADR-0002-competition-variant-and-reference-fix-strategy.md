# ADR-0002: Competition Variant and Reference Fix Strategy

## Status

Accepted.

## Context

Sentinel AML has secure owner workflows, a two-place PFR checker, and Wave 13
CHECK/HAVOC coverage before planned vulnerability waves start. Earlier wave
gates correctly rejected exploit and fix scripts because vulnerable behavior was
not yet in scope. Once vulnerability waves begin, that absolute rule would block
the competition package from carrying the vulnerable/fixed validation matrix
that an Attack-Defense service needs.

The competition package needs a repeatable strategy for proving all of these
states:

- the vulnerable variant is still checkable;
- the reference exploit succeeds against the vulnerable variant;
- the fixed variant is still checkable;
- the reference exploit is blocked by the fixed variant;
- fixes are narrow and do not pass by disabling business modules.

## Decision

Sentinel AML will use explicit competition matrix gates instead of a permanent
"no exploit scripts" rule after exploit waves start.

The matrix gate placeholders are:

- vulnerable checker gate;
- exploit-success gate;
- fixed checker gate;
- exploit-blocked gate;
- anti-coarse-fix gate.

Until the corresponding vulnerability and exploit waves are accepted, these
placeholders are structural contracts only. They must exist in docs, scripts,
and test coverage, but they must not introduce vulnerable behavior, reference
exploits, or reference fixes early.

When a vulnerability wave opens, the vulnerable checker gate must prove the
vulnerable profile still supports normal owner PUT/GET and CHECK/HAVOC. When
the matching exploit wave opens, the exploit-success gate must prove the
reference exploit extracts the intended flag only from the vulnerable profile.
When the matching reference-fix wave opens, the fixed checker gate must prove
owner PUT/GET and CHECK/HAVOC still pass, the exploit-blocked gate must prove
the exploit no longer extracts the flag, and the anti-coarse-fix gate must prove
the fix did not disable the affected business surface.

Reference fixes belong under `fixes/sentinel_aml/`. Reference exploits belong
under `sploits/sentinel_aml/` only in their scheduled exploit waves.

## Variant Rules

- Variants must be selected by build/test packaging or source profiles, not by
  HTTP debug/admin toggles.
- No `/debug`, `/admin`, `/api/debug`, `/api/admin`, checker-only, shell, or
  direct database shortcut may be added to switch variants or satisfy a gate.
- Vulnerable behavior must be intentional, wave-scoped, documented, and paired
  with exploit-positive tests.
- Fixed behavior must be narrow and preserve the owner checker path and the
  affected business module.
- Public attack data remains credential-free and raw-flag-free in every
  variant.

## Consequences

Historical pre-exploit gates may continue to assert that no exploit or fix
scripts exist for their branch context. Current and future competition gates
should instead validate the vulnerable/fixed matrix appropriate to the active
wave. This prevents gate drift: the repository can later contain reference
exploits and fixes without weakening the requirement that they run only in the
right matrix cell.

The first executable implementation of the matrix is allowed to be a placeholder
gate that checks the contract, artifacts, and absence of debug/admin variant
toggles. Later waves must replace placeholder matrix cells with concrete
commands as vulnerable and fixed variants become available.
