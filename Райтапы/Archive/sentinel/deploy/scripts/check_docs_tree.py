#!/usr/bin/env python3
"""Validate documentation tree presence for the Wave 01 gate."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


REQUIRED_DOCS = [
    "00_project_overview.md",
    "01_ctf_contract.md",
    "02_domain_model.md",
    "03_api_contract.md",
    "04_database_model.md",
    "05_authentication_authorization.md",
    "06_visibility_and_projections.md",
    "07_flag_stores.md",
    "08_checker_design.md",
    "09_vulnerability_matrix.md",
    "10_workers_and_async_flows.md",
    "11_deployment.md",
    "12_testing_strategy.md",
    "13_roadmap.md",
    "14_agent_execution_log.md",
    "15_risk_register.md",
    "source_of_truth_map.md",
    "definition_of_done.md",
    "open_questions.md",
    "aml_investigation_flows.md",
    "audit_export_graph_invariants.md",
    "network_room_model.md",
    "waves.md",
]

REQUIRED_DIRS = [
    "decisions",
    "agent_packets",
    "wave_reports",
]

REQUIRED_AGENT_PACKETS = [
    "wave_01_prompt_pool.md",
    "wave_01_fix_prompt_pool.md",
]

FORBIDDEN_ROOT_PROMPT_POOLS = [
    "wave_01_prompt_pool.md",
    "wave_01_fix_prompt_pool.md",
    "wave_02_prompt_pool.md",
    "wave_02_fix_prompt_pool.md",
]

REQUIRED_ROADMAP_MARKERS = [
    "W01",
    "W02",
    "W03",
    "W04",
    "W05",
    "W06",
    "W07",
    "W08",
    "W09",
    "W10",
    "W11",
    "W12",
    "W13",
    "W14",
    "W15",
    "W16",
    "W17",
    "W18",
    "W19",
    "W20",
    "W21",
    "W22",
    "W23",
    "W24",
    "W25",
    "W26",
    "W27",
    "W28",
    "W29",
    "W30",
    "aml_dedup_preview.py",
    "aml_audit_timeline.py",
    "aml_related_graph.py",
    "aml_export_redaction.py",
    "aml_network_room.py",
]

LEGACY_FILENAME_MARKERS = [
    "(",
    "exchange_invariants",
    "matching_engine",
    "ledger_and_balances",
    "market_simulator",
]

LEGACY_CONTENT_MARKERS = [
    "VoltaX",
    "paper-trading",
    "cryptocurrency exchange",
    "Ruby 3.3",
    "Sinatra",
    "Roda",
    "Sequel",
    "Puma",
]

IGNORED_DOC_PREFIXES = (
    ("archive",),
    ("wave_reports",),
)

IGNORED_DOC_FILES = {
    ("14_agent_execution_log.md",),
}


def validate_docs_tree(repo_root: Path) -> dict[str, Any]:
    docs_dir = repo_root / "docs"
    checks: list[dict[str, Any]] = []

    if not docs_dir.is_dir():
        return {
            "status": "fail",
            "checks": [{"path": "docs", "status": "fail", "message": "docs directory is missing"}],
        }

    for doc_name in REQUIRED_DOCS:
        path = docs_dir / doc_name
        checks.append(
            {
                "name": "required-doc",
                "path": f"docs/{doc_name}",
                "status": "pass" if path.is_file() else "fail",
                "message": "" if path.is_file() else "required canonical Sentinel AML document missing",
            }
        )

    for dir_name in REQUIRED_DIRS:
        path = docs_dir / dir_name
        checks.append(
            {
                "name": "required-dir",
                "path": f"docs/{dir_name}/",
                "status": "pass" if path.is_dir() else "fail",
                "message": "" if path.is_dir() else "required documentation directory missing",
            }
        )

    checks.extend(check_agent_packets(docs_dir))
    checks.extend(check_non_collapsed_roadmap(docs_dir))
    checks.extend(check_no_legacy_active_docs(docs_dir))

    return {"status": aggregate_status(checks), "checks": checks}


def check_agent_packets(docs_dir: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    packet_dir = docs_dir / "agent_packets"

    for packet_name in REQUIRED_AGENT_PACKETS:
        path = packet_dir / packet_name
        checks.append(
            {
                "name": "required-agent-packet",
                "path": f"docs/agent_packets/{packet_name}",
                "status": "pass" if path.is_file() else "fail",
                "message": "" if path.is_file() else "required prompt pool missing from canonical agent packet directory",
            }
        )

    misplaced = [name for name in FORBIDDEN_ROOT_PROMPT_POOLS if (docs_dir / name).exists()]
    checks.append(
        {
            "name": "no-root-prompt-pools",
            "path": "docs/",
            "status": "pass" if not misplaced else "fail",
            "message": "" if not misplaced else f"root-level prompt pools are non-canonical: {', '.join(misplaced)}",
        }
    )
    return checks


def check_non_collapsed_roadmap(docs_dir: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for filename in ("13_roadmap.md", "waves.md"):
        path = docs_dir / filename
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        missing = [marker for marker in REQUIRED_ROADMAP_MARKERS if marker not in text]
        collapsed = "Later Waves" in text or "Future Waves" in text
        checks.append(
            {
                "name": "roadmap-wave-detail",
                "path": f"docs/{filename}",
                "status": "pass" if not missing and not collapsed else "fail",
                "message": "" if not missing and not collapsed else f"missing={', '.join(missing)} collapsed={collapsed}",
            }
        )
    return checks


def check_no_legacy_active_docs(docs_dir: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    legacy_filenames: list[str] = []
    legacy_content: list[str] = []

    for path in docs_dir.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(docs_dir)
        if is_ignored_doc(relative):
            continue

        display_path = "docs/" + relative.as_posix()
        if any(marker in path.name for marker in LEGACY_FILENAME_MARKERS):
            legacy_filenames.append(display_path)

        if path.suffix.lower() not in {".md", ".txt"}:
            continue
        text = path.read_text(encoding="utf-8")
        for marker in LEGACY_CONTENT_MARKERS:
            if marker in text and "archive/foreign_voltax" not in text:
                legacy_content.append(f"{display_path}: {marker}")
                break

    checks.append(
        {
            "name": "no-active-legacy-filenames",
            "path": "docs/",
            "status": "pass" if not legacy_filenames else "fail",
            "message": "" if not legacy_filenames else "; ".join(sorted(legacy_filenames)),
        }
    )
    checks.append(
        {
            "name": "no-active-legacy-content",
            "path": "docs/",
            "status": "pass" if not legacy_content else "fail",
            "message": "" if not legacy_content else "; ".join(sorted(legacy_content)),
        }
    )
    return checks


def is_ignored_doc(relative: Path) -> bool:
    parts = relative.parts
    return (
        any(parts[: len(prefix)] == prefix for prefix in IGNORED_DOC_PREFIXES)
        or parts in IGNORED_DOC_FILES
    )


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    statuses = {check["status"] for check in checks}
    if "fail" in statuses:
        return "fail"
    return "pass"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    result = validate_docs_tree(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
