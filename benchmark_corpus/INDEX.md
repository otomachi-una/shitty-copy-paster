# Public A/D CTF benchmark sources

Collected 2026-11-19 for cross-event benchmarking of source-code audits, exploit/solver generation, and patches. The rows below point to organizers' public repositories; they are not copied into the benchmark inputs.

## Russian CTF Cup and C4T BuT S4D A/D sets

These are the best fit for the current service-audit workflow: service source, checkers, and exploit/sploit material are together in the repositories. Across the listed sets there are **43 services in 10 repositories**.

| Event | Services | Repository and ground-truth contents |
|---|---:|---|
| CTF Cup 2025 A/D | 4 | [ctfcup2025-ad](https://github.com/acisoru/ctfcup2025-ad) — `veladora`, `archive`, `warehouse`, `prototyper`; has `services/`, `checkers/`, `sploits/`, and `writeups/`. |
| CTF Cup 2024 A/D | 4 | [ctfcup-2024-ad](https://github.com/C4T-BuT-S4D/ctfcup-2024-ad) — `aquarius`, `crypter`, `docs`, `ark`; source, checkers, sploits. |
| CTF Cup 2023 A/D | 4 | [ctfcup-2023-ad](https://github.com/C4T-BuT-S4D/ctfcup-2023-ad) — `explorers`, `oilmarket`, `bluwal`, `neftetochka`; source, checkers, sploits. |
| CTF Cup 2022 Stage 2 | 4 | [ctfcup-2022-stage2](https://github.com/C4T-BuT-S4D/ctfcup-2022-stage2) — `flexinpoint`, `great_mettender`, `nucreport`, `хлебzаvод`; source, checkers, sploits, and a writeups section. |
| CTF Cup 2022 Stage 3 Part 1 | 1 | [ctfcup-2022-stage3-part1](https://github.com/C4T-BuT-S4D/ctfcup-2022-stage3-part1) — `KawaiGazpromBank`; source, checker, sploit. |
| Stay ~/ CTF 2022 | 6 | [stay-home-ctf-2022](https://github.com/C4T-BuT-S4D/stay-home-ctf-2022) — six services, source/checkers/sploits; writeups for three. |
| Stay ~/ CTF 2020 | 7 | [stay-home-ctf-2020](https://github.com/C4T-BuT-S4D/stay-home-ctf-2020) — seven services, source/checkers/sploits; a writeup for `msp`. |
| Gold CTF 2024 | 5 | [goldctf-2024](https://github.com/C4T-BuT-S4D/goldctf-2024) — five services, source/checkers/sploits, and writeups for all five. |
| BRICS+ CTF 2024 Finals | 4 | [bricsctf-2024-finals](https://github.com/C4T-BuT-S4D/bricsctf-2024-finals) — four services, source/checkers/exploits, and writeups for all four. |
| BRICS+ CTF 2023 Finals | 4 | [bricsctf-2023-stage2](https://github.com/C4T-BuT-S4D/bricsctf-2023-stage2) — four services, source/checkers/exploits, and writeups for all four. |

The CTF Cup 2024 and 2023 repositories each list four A/D services and their sploits; the 2022 Stage 2 repository also lists writeups. See the linked repository READMEs for the service names and per-task ground truth.

### Russian CTF Cup task-based sets (supplemental)

These add challenge variety, but they are Jeopardy/task-based rather than the service-oriented A/D format above:

- [CTF Cup 2024 qualifiers](https://github.com/C4T-BuT-S4D/ctfcup-2024-quals) — repository describes source code, writeups, exploits, and deployment files; the event report counts 17 tasks.
- [CTF Cup 2022 qualifiers](https://github.com/acisoru/ctfcup22-quals) — 23 listed challenges with source, writeups, and exploits.
- The [C4T-BuT-S4D repository list](https://github.com/orgs/C4T-BuT-S4D/repositories) and [ACISO repository list](https://github.com/acisoru?tab=repositories) expose additional years and event collections.

## FAUST CTF

The [FAUST GitHub organization](https://github.com/fausecteam) has **67 repositories named `faustctf-YYYY-*` across 2017–2026** in the public repository listing checked for this index. These are per-service archives; contents vary by service, so check whether each repository has an exploit, spoiler, patch, or a linked team writeup before using it as scored ground truth.

Recent collections with eight services each:

- [FAUST CTF 2024](https://github.com/orgs/fausecteam/repositories?q=faustctf-2024) — `lvm`, `quickr-maps`, `floppcraft`, `todo-list-service`, `faust-vault`, `asm_chat`, `secretchannel`, `missions`. The `todo-list-service` repository has `exploits/` and `patches/` directories.
- [FAUST CTF 2023](https://github.com/orgs/fausecteam/repositories?q=faustctf-2023) — eight per-service repositories, including [Jokes](https://github.com/fausecteam/faustctf-2023-jokes), [Chat App](https://github.com/fausecteam/faustctf-2023-chat-app), and [Auction Service](https://github.com/fausecteam/faustctf-2023-auction-service).
- [FAUST CTF 2022](https://github.com/orgs/fausecteam/repositories?q=faustctf-2022) — eight per-service repositories. [Ghost](https://github.com/fausecteam/faustctf-2022-ghost) includes service/checker/exploit material and `README.SPOILER.md`.

Other useful recent repositories include the five [FAUST CTF 2025 services](https://github.com/orgs/fausecteam/repositories?q=faustctf-2025) and four [FAUST CTF 2026 services](https://github.com/orgs/fausecteam/repositories?q=faustctf-2026). Third-party FAUST writeups can also be found through [CTFtime's FAUST team page](https://ctftime.org/team/550) and linked writeup pages.

## ENOWARS

The [ENOWARS documentation points to its previous service repositories](https://enowars.github.io/docs/). The public GitHub listing contained **50 repositories matching `enowarsN-service-*` across editions 3–10** when checked. Counts by edition: 3: 8, 4: 5, 5: 3, 6: 3, 7: 10, 8: 7, 9: 8, 10: 6. Browse the [ENOWARS repositories](https://github.com/orgs/enowars/repositories) and select the service repos; not every service archive has an equally complete writeup.

Two high-value newer examples:

- [FlagDrive, ENOWARS 10](https://github.com/enowars/enowars10-service-flagdrive) — `main` is documented as vulnerable, `fixed` contains a patched version, and the repository documents three flagstore vulnerability paths.
- [Funsplash, ENOWARS 10](https://github.com/enowars/enowars10-service-funsplash) — service, checker, and documentation for a three-flagstore challenge.

The organization also has multipart [ENOWARS 7](https://github.com/enowars/dump-enowars7) and [ENOWARS 8](https://github.com/enowars/dump-enowars8) dumps; the per-service repositories are easier to feed into the current one-folder-at-a-time workflow.

## Benchmark hygiene

Keep the task input and ground truth apart. Before sending any repository to a model, exclude `sploits/`, `exploits/`, `writeups/`, spoiler/readme files, patch directories, and fixed-version branches. Record the exact vulnerable commit/branch used, and score findings against the saved ground truth after the model run. Some repositories intentionally publish the fix alongside the vulnerable source.
