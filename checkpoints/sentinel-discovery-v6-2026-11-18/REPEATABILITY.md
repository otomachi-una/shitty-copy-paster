# v6 repeatability comparison

Prompt, task input, provider, and six-message design were held constant across the baseline and two fresh Qwen contexts. Ground truth was consulted only after each response was saved.

| Benchmark issue | Baseline v6 | Repeat 1 | Repeat 2 | Assessment |
|---|---|---|---|---|
| AML-1 duplicate preview | surfaced | surfaced | surfaced | Stable leak path; all three attributed it to missing candidate ownership, while the organizer fix removes private review-context evidence from the shared preview. |
| AML-2 activity detail | surfaced | surfaced | missed | Two runs found the note-body path but blamed a missing owner check; the ground-truth defect is Redacted causing collaborator detail. |
| AML-3 graph EDD summary | surfaced | surfaced | missed | Correct root cause in the first two runs. |
| AML-4 linked export | surfaced as export leak | surfaced as export leak | merged into AML-1 | The first two runs attributed it to the duplicate resolver; they missed the Root-versus-Linked export context error. |
| AML-5 network-room dossier | surfaced as artifact leak | surfaced as artifact leak | dismissed as intentional | The first two runs blamed materialization; the ground-truth defect is dossier projection ignoring CoveragePolicy. |

Two of three runs surfaced all five affected areas; repeat 2 surfaced AML-1 alone and treated AML-5 as intentional. Root-cause attribution is still unreliable. Keep this prompt frozen while interpreting these runs; refine it before spending time on solver generation or broad cross-task claims.

## Decision

The same-task repeats were the right first experiment and show that the five-area result is not yet stable enough to call reliable. Next, tighten the discovery prompt around source-to-sink policy decisions and exact helper context, then repeat against Sentinel. After same-task behavior is stable, test two different services for generalization. Keep solver and patch prompts as a later, separate phase.
