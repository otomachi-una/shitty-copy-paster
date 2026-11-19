# Wave 33 Leak Scanner

## Summary

W33-T02 adds a player-facing hygiene scanner for candidate player trees or
archives. The scanner is intentionally scoped to generated player candidates,
not the organizer repository, so organizer-only checker, sploit, fix, test,
gate, and wave evidence can remain intact internally.

No product code, checker behavior, sploit behavior, fix patch semantics,
migrations, Docker runtime, or release archive behavior changed.

## Scanner Policy

`scripts/check_player_bundle_hygiene.py` accepts an explicit candidate path and
supports directories, tar archives, and zip archives. It fails when the
candidate path is the organizer repository root.

Default forbidden player-bundle path prefixes:

- `checkers/`
- `sploits/`
- `exploits/`
- `fixes/`
- `tests/`
- `scripts/`
- `docs/`

Default denied path/content tokens:

- `vulnerable`
- `aml1`, `aml2`, `aml3`, `aml4`, `aml5`
- `AML-1`, `AML-2`, `AML-3`, `AML-4`, `AML-5`
- `exploit`
- `sploit`
- `fixes`
- `checker`
- `flag`
- `attack_info`
- `public_attack_data`
- `LEAK_TARGET`
- `MUST_NOT_LEAK`
- `checker_secret`

The scanner reports JSON with one `candidate-boundary` check and one
`player-bundle-leak-scan` check. It exits 0 only when all checks pass.

## Candidate Scope

The scanner runs on player candidates because the organizer repository is
supposed to contain organizer-only evidence. Scanning the whole repository as if
it were player-facing would produce known true positives and pressure agents to
delete required checker/sploit/fix evidence. The correct workflow is:

1. build or stage a candidate player tree/archive;
2. scan that candidate;
3. fail closed if organizer-only paths or challenge-map tokens appear;
4. use a narrowly reviewed JSON allowlist only for intentional neutral context.

`scripts/build_player_bundle.py` is a stub/allowlist generator for gate smoke
checks only. It creates a minimal sanitized candidate outside the repository and
does not build final release archives.

## False-Positive Handling

False positives must be handled by the candidate builder first: rename,
rewrite, or exclude the leaking player-facing file. A JSON allowlist is allowed
only for carefully reviewed neutral contexts, with entries shaped as:

```json
{
  "allow": [
    {"type": "content-token", "path": "README.md", "tokens": ["flag"]}
  ]
}
```

Allowlist entry types are `content-token`, `path-token`, `forbidden-path`, or
`*`. Allowlisting `forbidden-path` should require reviewer approval because it
can reintroduce organizer-only directories.

## Examples

Caught leaks:

- `bin/aml1_vulnerable_helper.txt` fails on `aml1` and `vulnerable` path
  tokens.
- `config/attack_info.txt` fails on the `attack_info` path token.
- file content containing `LEAK_TARGET=MUST_NOT_LEAK checker_secret flag` fails
  on `LEAK_TARGET`, `MUST_NOT_LEAK`, `checker_secret`, and `flag`.
- candidate directories such as `checkers/`, `sploits/`, `fixes/`, `tests/`,
  and `docs/` fail immediately as forbidden player-bundle prefixes.
- archive members such as `../README.md` fail as unsafe member paths.

Allowed neutral terms:

- customer onboarding;
- account monitoring;
- transaction review;
- alerts and cases;
- due diligence;
- risk scoring;
- audit events;
- entity graph;
- export;
- network rooms.

## Make Target

`make player-hygiene-gate` is wired to:

- run `python -B -m unittest discover -s tests -p "test_player_bundle_hygiene.py"`;
- scan `PLAYER_BUNDLE=...` when a candidate path is supplied;
- otherwise generate a stub candidate with `scripts/build_player_bundle.py` and
  scan it with `scripts/check_player_bundle_hygiene.py`.

The target does not call `release-archive` or `scripts/build_release_archive.py`.

## Tests Run

- `python -B -m py_compile scripts\check_player_bundle_hygiene.py scripts\build_player_bundle.py` -
  exit 0.
- `python -B -m unittest discover -s tests -p "test_player_bundle_hygiene.py"` -
  exit 0, 12 tests in 0.300s.
- `python -B scripts\build_player_bundle.py --output-dir <temp-candidate>` plus
  `python -B scripts\check_player_bundle_hygiene.py <temp-candidate>` - exit 0;
  scanned 18 candidate members.
- `python -B scripts\check_player_bundle_hygiene.py <synthetic-leaking-candidate>` -
  expected exit 1; caught `attack_info`, `checker`, `flag`, `LEAK_TARGET`,
  `MUST_NOT_LEAK`, and `checker_secret`.
- `python -B scripts\check_docs_tree.py` - exit 0.

`make player-hygiene-gate` could not be executed literally in this Windows
shell because `make` is not installed. The Makefile target was statically
validated by unit tests, and the underlying commands were run directly.

## CTF and Security Invariants

- Organizer-only checker, sploit, fix, vulnerable-profile, CHECK/HAVOC, and
  exploit-blocking evidence remains in the organizer repository.
- The scanner fails closed for obvious challenge-map leaks in player candidates.
- The scanner does not require deleting organizer-only evidence and refuses to
  treat the organizer repository root as a player candidate.
- Candidate player artifacts must exclude checker credentials, flags,
  attack-info schemas beyond public gameplay needs, reference exploit paths,
  fix patches, wave docs, and vulnerability maps.

## Risks

- The denylist is intentionally conservative and may require future allowlist
  entries for neutral player docs.
- Binary/image candidates may contain embedded strings from build metadata;
  future package builders should strip or neutralize source paths and symbols
  before scanning.
- The stub bundle generator is not a final package builder.

## Ready for Review

Yes, for player-facing leak scanner and denylist-gate tooling.
