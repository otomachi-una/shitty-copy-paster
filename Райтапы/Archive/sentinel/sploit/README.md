# Sentinel AML Reference Exploits

This directory contains reviewed reference exploits for `sentinel_aml`.

Reference exploits remain separate from the checker. They must use public attack
data and normal HTTP product APIs only; no exploit may rely on checker-private
state, leaked credentials, direct database access, shell access, debug/admin
routes, or reference-fix behavior.

Implemented scripts:

- `aml_dedup_preview.py`: Wave 19 AML-1 reference exploit for the
  case-match preview narrative mix-up. It consumes public place 1 attack data,
  creates an attacker-owned source case using the public matching reference, and
  extracts the flag only from the abnormal match explanation returned by the
  normal preview response.
- `aml_audit_timeline.py`: Wave 20 AML-2 reference exploit for the
  audit activity narrative overexposure. It consumes public place 1 attack data,
  registers/logs in as an attacker, requests only the normal related-entity
  activity side view, and extracts the flag only from an abnormal
  `activity_narrative` review context.
- `aml_related_graph.py`: Wave 21 AML-3 reference exploit for the
  related graph assessment-summary escalation. It consumes public place 2 attack
  data, registers/logs in as an attacker, creates only attacker-owned graph
  participation with the victim `entity_ref` / `party_ref`, requests only
  `GET /api/graph/entities/{entity_hint}/edd-summaries`, and extracts the flag
  only from an abnormal assessment summary.
- `aml_export_redaction.py`: Wave 22 AML-4 reference exploit for the
  dispute export evidence-expansion gap. It consumes public place 1 attack data,
  registers/logs in as an attacker, creates an attacker-owned case with the
  public matching reference, creates a normal dispute export, reads the stored
  export, and extracts the flag only from abnormal linked evidence content.
- `aml_network_room.py`: Wave 23 AML-5 reference exploit for the
  network-room dossier context bleed. It consumes public place 2 metadata,
  registers/logs in as an attacker, creates attacker-owned
  customer/account/transaction/alert/case objects using the public locator, and
  extracts the flag only from abnormal dossier context or evaluation blocks.

Locked future script names:

- `aml_network_room.py` (implemented in W23)

Reference fixes remain locked under `fixes/sentinel_aml/` until their scheduled
fix waves.
