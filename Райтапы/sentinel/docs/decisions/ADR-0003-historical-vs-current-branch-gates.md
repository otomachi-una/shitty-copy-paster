# ADR-0003: Historical vs Current-Branch Gates

## Status

Accepted.

## Context

Sentinel AML uses sequential waves to build a ForcAD/Hackerdom-compatible
Attack-Defense service. Early gate scripts were intentionally written as
point-in-time historical wave gates. For example, Wave 13 rejected vulnerable
profile markers because Wave 13 was the checker/HAVOC baseline before planned
vulnerability waves started. Wave 14 rejected AML-2 through AML-5 markers
because only AML-1 was in scope at that point. Wave 15 rejected AML-3 through
AML-5 markers because only AML-2 was in scope.

After Wave 16, the current branch intentionally contains AML-1, AML-2, and
AML-3 build-tag profiles. Re-running older point-in-time gates against the
current branch can therefore fail for the correct reason: they are enforcing a
past branch boundary, not the current aggregate competition state.

The orchestrator review host reported `make wave16-gate` exiting 0. That
current-branch aggregate result supersedes older liveness/blocker language for
Waves 13 through 16 without fabricating missing standalone Wave 14 or Wave 15
review artifacts.

## Decision

Sentinel AML distinguishes two classes of gates:

- point-in-time historical wave gates, such as `make wave13-gate`,
  `make wave14-gate`, and `make wave15-gate`, which may reject later-wave
  markers when run on a newer branch;
- current-branch aggregate gates, such as `make wave16-gate` and future A/D
  matrix gates, which are authoritative for the active branch state.

The roadmap and wave ledgers may mark Waves 13 through 16 complete when a later
current-branch aggregate gate has accepted their retained behavior and their
planned vulnerability profiles. Missing standalone review files for Wave 14 or
Wave 15 must be recorded as historical evidence gaps, not silently invented.

Wave 17 is unlocked after Wave 16 acceptance. Wave 18 remains planned in the
vulnerability sequence. Reference exploit and fix waves remain locked until
their planned sequence and prerequisite evidence.

## Alternatives

One alternative was to keep updating every older wave gate so it always passes
on the latest branch. That would blur the original point-in-time contract and
make it harder to see which future markers were forbidden when each wave was
reviewed.

Another alternative was to keep the status ledger blocked until every older
standalone gate passed on the current branch. That would make intentional
later-wave vulnerable profiles impossible to carry in the same repository and
would conflict with the competition matrix strategy in ADR-0002.

## Consequences

Historical gates remain useful as branch-era validators, but they are no longer
current-branch release gates after later scoped vulnerable profiles exist.
Current-branch aggregate gates must validate the retained checker behavior,
default secure profiles, active vulnerable profiles, locked exploit/fix cells,
and absence of broad leaks or debug/admin toggles.

Documentation must name which gate class is being cited. Validation summaries
must not imply that a historical gate failure caused by intentional later-wave
markers is a current release blocker.

## CTF Implications

The service keeps the A/D sequence intact:

- two checker flag stores remain active and owner-view-only;
- vulnerable behavior is introduced through build-tag profiles, not runtime
  debug/admin toggles;
- public attack data remains locator-only and credential-free;
- AML-1 through AML-3 vulnerable checker cells are concrete after Wave 16;
- AML-4 and AML-5 remain future vulnerability work;
- reference exploits and fixes remain locked until their scheduled waves.
