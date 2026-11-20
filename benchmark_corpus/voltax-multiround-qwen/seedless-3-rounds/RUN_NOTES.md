# VoltaX seedless three-round audit

Task source: `services/voltax-exchange` (94 collected files). No findings were seeded. The writeup was not included in any prompt. Qwen3.8-Max used a new Chromium profile for each round, and each temporary profile was removed after its round.

## Results

| Round | Confirmed findings | Change |
|---|---:|---|
| 1 | 2 | Found EX-1 and EX-3 |
| 2 | 2 | Unchanged |
| 3 | 2 | Unchanged |

The final report maps to two of the writeup's five issues. F1 matches EX-1, the cross-account order reference lookup. F2 matches EX-3, the counterparty booking reference in trade detail. The audit omitted EX-2 (RFQ workup terms), EX-4 (broker report booking marker), and EX-5 (public-feed strategy context). No confirmed finding was unmatched to the writeup.

## Comparison

The prior one-session v16 run confirmed four of five writeup issues and left EX-2 as an unresolved lead. The seedless three-round run confirmed two of five and did not mention those three issues. A separate seeded two-round run confirmed all five by promoting the carried EX-2 lead. That result measured follow-up on an existing lead. It did not show that repeated rounds independently recover missed findings.

The comparison is not a controlled test of round count alone. The v16 workflow used a staged map and focused audit passes. The seedless `review` workflow sent the source parts and then one general audit request per round. The prompt design differs as well as the seeding.

Round times were 205 seconds, 552 seconds, and 202 seconds, for 959 seconds total. CAPTCHA verification was required during the run.
