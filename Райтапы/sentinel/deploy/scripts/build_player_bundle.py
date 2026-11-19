#!/usr/bin/env python3
"""Build a sanitized player-service candidate tree.

This script stages a candidate directory for later packaging review. It does
not create final archives, manifests, checksums, or promoted release artifacts.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = ROOT / "tmp" / "player-service-candidate"
IGNORED_REPO_OUTPUT_DIRS = {"tmp", "temp"}

ROOT_FILES: tuple[str, ...] = ("go.mod", "go.sum")
SOURCE_DIRS: tuple[str, ...] = ("cmd", "internal", "migrations")
BUILD_SOURCE_DIRS: tuple[str, ...] = ("cmd", "internal", "migrations")
DEFAULT_FRONTEND_DIST_DIR = ROOT / "frontend" / "dist"
VENDOR_DIR = "vendor"
PACKAGING_STATUS_FILE = "PACKAGING_STATUS.json"
COMPETITION_TAGS = (
    "case_match_preview",
    "audit_detail_view",
    "entity_review_summary",
    "linked_case_export_detail",
    "network_room_detail",
)
PLAYER_SOURCE_OMIT_PATHS = {
    "internal/exporting/export_profile_default.go",
    "internal/httpapi/audit_profile_default.go",
    "internal/httpapi/dedup_profile_default.go",
    "internal/httpapi/export_profile_default.go",
    "internal/httpapi/graph_profile_default.go",
    "internal/httpapi/network_room_profile_default.go",
}
PLAYER_SOURCE_RENAMES = {
    "internal/exporting/export_profile_linked_case.go": "internal/exporting/export_policy.go",
    "internal/graph/repository_entity_review.go": "internal/graph/repository_entity_access.go",
    "internal/httpapi/audit_profile_detail.go": "internal/httpapi/audit_policy.go",
    "internal/httpapi/dedup_profile_case_match.go": "internal/httpapi/dedup_policy.go",
    "internal/httpapi/export_profile_linked_case.go": "internal/httpapi/export_policy.go",
    "internal/httpapi/graph_profile_entity_review.go": "internal/httpapi/graph_policy.go",
    "internal/httpapi/network_room_profile_detail.go": "internal/httpapi/network_room_policy.go",
    "internal/networkroom/dossier_profile_room_detail.go": "internal/networkroom/dossier_policy.go",
    "internal/networkroom/repository_room_detail.go": "internal/networkroom/repository_room_access.go",
}
PLAYER_PACKAGE_STATUS: dict[str, object] = {
    "artifact_class": "player-service",
    "package_role": "team-runtime",
    "delivery_mode": "binary-image",
    "artifact_contract": "player-service-with-ui.v1",
    "runtime_layout": "prebuilt service binaries with container runtime templates",
    "runtime_requirements": {
        "container_runtime": "Docker with Compose support",
        "database": "PostgreSQL reachable through DATABASE_URL",
        "http_gateway_port": "SENTINEL_AML_HTTP_PORT, default 80",
    },
    "delivered_components": [
        {
            "key": "backend-runtime",
            "delivery_path": "bin/",
            "included": True,
            "required": True,
        },
        {
            "key": "participant-ui",
            "delivery_path": "ui/",
            "included": False,
            "required": True,
        },
    ],
    "participant_ui": {
        "artifact_class": "runtime-dist",
        "delivery_path": "ui/",
        "runtime_config": "ui/runtime-config.js",
        "included": False,
        "required": True,
    },
    "runtime_validation": {
        "status": "external-required",
        "summary_path": "out/artifact-first-validation-summary.json",
        "reason": "Live deployment validation is recorded outside this package when run.",
    },
}
BINARY_TARGETS: tuple[tuple[str, str], ...] = (
    ("bin/aml-api", "./cmd/aml-api"),
    ("bin/aml-worker", "./cmd/aml-worker"),
    ("bin/aml-migrate", "./scripts/migrate"),
)
FRONTEND_DIST_REQUIRED_FILES = ("index.html", "runtime-config.js")
FRONTEND_DIST_FORBIDDEN_DIR_NAMES = {
    ".playwright",
    ".vite",
    "blob-report",
    "e2e",
    "node_modules",
    "playwright-report",
    "scripts",
    "src",
    "test-results",
    "tests",
}
FRONTEND_DIST_FORBIDDEN_FILE_NAMES = {
    "package-lock.json",
    "package.json",
    "playwright.config.ts",
    "README.md",
    "tsconfig.app.json",
    "tsconfig.json",
    "tsconfig.node.json",
    "vite.config.ts",
}
FRONTEND_DIST_FORBIDDEN_SUFFIXES = {
    ".map",
    ".ts",
    ".tsx",
    ".tsbuildinfo",
}
EXCLUDED_DIR_NAMES = {
    ".git",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".vscode",
    "__pycache__",
    "bin",
    "tmp",
    "temp",
}
EXCLUDED_FILE_SUFFIXES = {
    ".coverprofile",
    ".exe",
    ".pyc",
    ".pyo",
    ".test",
}
EXCLUDED_FILE_SUFFIX_CHAINS = (
    ".tar.gz",
)
VENDOR_FILE_ALLOW_SUFFIXES = {
    ".c",
    ".go",
    ".h",
    ".inc",
    ".s",
    ".sum",
    ".txt",
}
LEGACY_PROFILE_TAGS = (
    "aml1_vulnerable",
    "aml2_vulnerable",
    "aml3_vulnerable",
    "aml4_vulnerable",
    "aml5_vulnerable",
)
SOURCE_TOKEN_REPLACEMENTS = {
    '"checker_private"': '"restricted_audit_field"',
    '"flag_value"': '"restricted_audit_value"',
    '"secret_for_checker"': '"sensitive_service_secret"',
    "caseMatchPreviewProfileEnabled": "caseMatchPreviewPolicyEnabled",
    "auditDetailProfileEnabled": "auditDetailPolicyEnabled",
    "caseAuditViewsForProfile": "caseAuditViewsForPolicy",
    "entityActivityViewsForProfile": "entityActivityViewsForPolicy",
    "entityReviewSummaryProfileEnabled": "entityReviewSummaryPolicyEnabled",
    "graphEDDSummariesResponseForProfile": "graphEDDSummariesResponseForPolicy",
    "linkedCaseExportProfileEnabled": "linkedCaseExportPolicyEnabled",
    "appendExportProfileData": "appendExportPolicyData",
    "populateExportLinkedCaseProfileData": "populateExportLinkedCasePolicyData",
    "cloneExportProfileMaps": "cloneExportPolicyMaps",
    "networkRoomDetailProfileEnabled": "networkRoomDetailPolicyEnabled",
    "networkRoomDossierResponseForProfile": "networkRoomDossierResponseForPolicy",
}


def build_player_candidate(
    output_dir: Path,
    allowlist_out: Path | None = None,
    frontend_dist_dir: Path | None = DEFAULT_FRONTEND_DIST_DIR,
    *,
    require_participant_ui: bool = True,
) -> dict[str, Any]:
    output_dir = output_dir.resolve()
    ensure_candidate_output_allowed(output_dir)
    if allowlist_out is None:
        allowlist_out = output_dir.parent / f"{output_dir.name}.hygiene-allowlist.json"
    allowlist_out = allowlist_out.resolve()
    ensure_sidecar_output_allowed(allowlist_out, output_dir)

    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    if require_participant_ui and frontend_dist_dir is None:
        raise ValueError("canonical player artifact requires participant UI runtime files; provide frontend_dist_dir")
    frontend_result = copy_frontend_ui_dist(frontend_dist_dir, output_dir / "ui") if frontend_dist_dir else None
    if require_participant_ui and frontend_result is None:
        raise ValueError("canonical player artifact requires participant UI runtime files")
    write_generated_player_files(output_dir, include_frontend_ui=frontend_result is not None)
    binary_result = build_player_binaries(output_dir / "bin")
    write_packaging_status(output_dir, frontend_result, binary_result)
    copy_tree(ROOT / "migrations", output_dir / "migrations")

    allowlist = player_hygiene_allowlist()
    allowlist_out.parent.mkdir(parents=True, exist_ok=True)
    allowlist_out.write_text(json.dumps(allowlist, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    run_ctf_disclosure_hygiene(output_dir, allowlist_out)

    files = inventory(output_dir)
    return {
        "status": "pass",
        "candidate_type": "player-service",
        "output_dir": str(output_dir),
        "allowlist": str(allowlist_out),
        "binaries": binary_result,
        "frontend_ui": frontend_result,
        "file_count": len(files),
        "files": files,
    }


def build_stub_player_candidate(output_dir: Path) -> dict[str, Any]:
    """Compatibility helper for W33-T02 hygiene tests."""

    output_dir = output_dir.resolve()
    ensure_candidate_output_allowed(output_dir)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    files = {
        "README.md": (
            "# Sentinel AML Player Service\n\n"
            "This minimal package contains neutral runtime placeholders for hygiene scanning.\n"
        ),
        "bin/aml-api.placeholder": "compiled service binary placeholder\n",
        "bin/aml-worker.placeholder": "compiled worker binary placeholder\n",
        "config/player.env.example": "DATABASE_URL=postgres://user:pass@postgres:5432/sentinel\n",
        "deploy/compose.yaml": "services:\n  api:\n    image: sentinel-aml-player:latest\n",
    }
    for relative, content in files.items():
        path = output_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")

    migrations_dir = output_dir / "migrations"
    migrations_dir.mkdir()
    for migration in sorted((ROOT / "migrations").glob("*.sql")):
        copy_file(migration, migrations_dir / migration.name)

    files_inventory = inventory(output_dir)
    return {
        "status": "pass",
        "candidate_type": "player-service-smoke",
        "output_dir": str(output_dir),
        "file_count": len(files_inventory),
        "files": files_inventory,
    }


def ensure_candidate_output_allowed(output_dir: Path) -> None:
    if output_dir == ROOT:
        raise ValueError("candidate output must not be the organizer repository root")
    try:
        relative = output_dir.relative_to(ROOT)
    except ValueError:
        return
    if not relative.parts or relative.parts[0] not in IGNORED_REPO_OUTPUT_DIRS:
        raise ValueError("repo-local candidate output must be under ignored tmp/ or temp/")


def ensure_sidecar_output_allowed(sidecar: Path, output_dir: Path) -> None:
    if sidecar == output_dir or output_dir in sidecar.parents:
        raise ValueError("hygiene allowlist sidecar must not be inside the player candidate")
    ensure_candidate_output_allowed(sidecar.parent)


def write_generated_player_files(output_dir: Path, *, include_frontend_ui: bool = False) -> None:
    compose_gateway_service = ""
    if include_frontend_ui:
        compose_gateway_service = (
            "  gateway:\n"
            "    image: nginx:1.27-alpine\n"
            "    volumes:\n"
            "      - ../ui:/usr/share/nginx/html:ro\n"
            "      - ../config/ui.nginx.conf:/etc/nginx/conf.d/default.conf:ro\n"
            "    depends_on:\n"
            "      api:\n"
            "        condition: service_started\n"
            "    ports:\n"
            "      - \"${SENTINEL_AML_HTTP_PORT:-80}:80\"\n"
        )
    generated = {
        "README.md": read_packaging_doc("README.md"),
        "TROUBLESHOOTING.md": read_packaging_doc("TROUBLESHOOTING.md"),
        "Dockerfile": (
            "FROM alpine:3.20\n"
            "WORKDIR /app\n"
            "COPY bin/aml-api /app/aml-api\n"
            "COPY bin/aml-worker /app/aml-worker\n"
            "COPY bin/aml-migrate /app/aml-migrate\n"
            "COPY migrations /app/migrations\n"
            "RUN chmod +x /app/aml-api /app/aml-worker /app/aml-migrate\n"
            "EXPOSE 8080\n"
            "CMD [\"/app/aml-api\", \"-addr\", \":8080\"]\n"
        ),
        "config/player.env.example": (
            "DATABASE_URL=postgres://sentinel:sentinel@postgres:5432/sentinel_aml?sslmode=disable\n"
            "SENTINEL_AML_HTTP_PORT=80\n"
        ),
        "config/ui.nginx.conf": (
            "server {\n"
            "  listen 80;\n"
            "  root /usr/share/nginx/html;\n"
            "  index index.html;\n"
            "\n"
            "  location /api/ {\n"
            "    proxy_pass http://api:8080;\n"
            "  }\n"
            "\n"
            "  location /healthz {\n"
            "    proxy_pass http://api:8080;\n"
            "  }\n"
            "\n"
            "  location /readyz {\n"
            "    proxy_pass http://api:8080;\n"
            "  }\n"
            "\n"
            "  location / {\n"
            "    try_files $uri $uri/ /index.html;\n"
            "  }\n"
            "}\n"
        ),
        "deploy/compose.yaml": (
            "services:\n"
            "  postgres:\n"
            "    image: postgres:16-alpine\n"
            "    environment:\n"
            "      POSTGRES_DB: sentinel_aml\n"
            "      POSTGRES_USER: sentinel\n"
            "      POSTGRES_PASSWORD: sentinel\n"
            "    volumes:\n"
            "      - sentinel_aml_pgdata:/var/lib/postgresql/data\n"
            "    healthcheck:\n"
            "      test: [\"CMD-SHELL\", \"pg_isready -U sentinel -d sentinel_aml\"]\n"
            "      interval: 2s\n"
            "      timeout: 5s\n"
            "      retries: 20\n"
            "  migrate:\n"
            "    build:\n"
            "      context: ..\n"
            "    command: [\"/app/aml-migrate\"]\n"
            "    environment:\n"
            "      DATABASE_URL: postgres://sentinel:sentinel@postgres:5432/sentinel_aml?sslmode=disable\n"
            "    depends_on:\n"
            "      postgres:\n"
            "        condition: service_healthy\n"
            "  api:\n"
            "    build:\n"
            "      context: ..\n"
            "    command: [\"/app/aml-api\", \"-addr\", \":8080\"]\n"
            "    environment:\n"
            "      DATABASE_URL: postgres://sentinel:sentinel@postgres:5432/sentinel_aml?sslmode=disable\n"
            "    depends_on:\n"
            "      migrate:\n"
            "        condition: service_completed_successfully\n"
            "  worker:\n"
            "    build:\n"
            "      context: ..\n"
            "    command: [\"/app/aml-worker\"]\n"
            "    environment:\n"
            "      DATABASE_URL: postgres://sentinel:sentinel@postgres:5432/sentinel_aml?sslmode=disable\n"
            "    depends_on:\n"
            "      migrate:\n"
            "        condition: service_completed_successfully\n"
            f"{compose_gateway_service}"
            "volumes:\n"
            "  sentinel_aml_pgdata:\n"
        ),
    }
    for relative, content in generated.items():
        path = output_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")


def competition_tags_arg() -> str:
    return " ".join(COMPETITION_TAGS)


def read_packaging_doc(name: str) -> str:
    return (ROOT / "packaging" / "player" / name).read_text(encoding="utf-8")


def write_packaging_status(
    output_dir: Path,
    frontend_result: dict[str, object] | None = None,
    binary_result: dict[str, object] | None = None,
) -> None:
    status = dict(PLAYER_PACKAGE_STATUS)
    participant_ui = dict(PLAYER_PACKAGE_STATUS["participant_ui"])  # type: ignore[index]
    delivered_components = [dict(component) for component in PLAYER_PACKAGE_STATUS["delivered_components"]]  # type: ignore[index]
    if frontend_result is not None:
        participant_ui["included"] = True
        participant_ui["file_count"] = frontend_result["file_count"]
        for component in delivered_components:
            if component.get("key") == "participant-ui":
                component["included"] = True
                component["file_count"] = frontend_result["file_count"]
    status["participant_ui"] = participant_ui
    status["delivered_components"] = delivered_components
    if binary_result is not None:
        status["binaries"] = {
            "included": True,
            "platform": binary_result["platform"],
            "targets": binary_result["targets"],
        }
    (output_dir / PACKAGING_STATUS_FILE).write_text(
        json.dumps(status, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def build_player_binaries(dest_dir: Path) -> dict[str, object]:
    dest_dir.mkdir(parents=True, exist_ok=True)
    built: list[str] = []
    with tempfile.TemporaryDirectory(prefix="sentinel-aml-player-build-") as tmp:
        build_root = Path(tmp) / "competition-source"
        materialize_competition_source(build_root)
        env = os.environ.copy()
        env.update(
            {
                "CGO_ENABLED": "0",
                "GOARCH": "amd64",
                "GOFLAGS": "-mod=vendor",
                "GOOS": "linux",
                "GOTELEMETRY": "off",
                "GOTOOLCHAIN": "local",
                "GOCACHE": str(Path(tmp) / "gocache"),
                "GOTMPDIR": str(Path(tmp) / "gotmp"),
            }
        )
        Path(env["GOCACHE"]).mkdir(parents=True, exist_ok=True)
        Path(env["GOTMPDIR"]).mkdir(parents=True, exist_ok=True)
        for relative, package in BINARY_TARGETS:
            output = dest_dir / Path(relative).name
            command = [
                "go",
                "build",
                "-trimpath",
                "-ldflags",
                "-s -w",
                "-o",
                str(output),
                package,
            ]
            completed = subprocess.run(command, cwd=build_root, env=env, capture_output=True, text=True)
            if completed.returncode != 0:
                detail = completed.stderr.strip() or completed.stdout.strip() or f"go build exited {completed.returncode}"
                raise RuntimeError(f"build participant service binary {Path(relative).name}: {detail}")
            built.append(relative)
    return {
        "artifact_class": "linux-amd64-service-binaries",
        "platform": "linux/amd64",
        "targets": built,
    }


def materialize_competition_source(dest_root: Path) -> dict[str, object]:
    """Stage the participant build tree with one neutral implementation selected."""

    if dest_root.exists():
        shutil.rmtree(dest_root)
    dest_root.mkdir(parents=True)
    for relative in ROOT_FILES:
        copy_file(ROOT / relative, dest_root / relative)
    for dirname in BUILD_SOURCE_DIRS:
        copy_tree(ROOT / dirname, dest_root / dirname)
    scripts_migrate = dest_root / "scripts" / "migrate"
    scripts_migrate.mkdir(parents=True, exist_ok=True)
    copy_file(ROOT / "scripts" / "migrate" / "main.go", scripts_migrate / "main.go")
    vendor = ROOT / VENDOR_DIR
    if vendor.exists():
        copy_vendor_tree(vendor, dest_root / VENDOR_DIR)
    return {
        "artifact_class": "materialized-competition-source",
        "path": str(dest_root),
        "files": inventory(dest_root),
    }


def run_ctf_disclosure_hygiene(output_dir: Path, allowlist_out: Path) -> None:
    checker = ROOT / "scripts" / "check_ctf_disclosure_hygiene.py"
    completed = subprocess.run(
        ["python", "-B", str(checker), str(output_dir), "--allowlist", str(allowlist_out)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stdout.strip() or completed.stderr.strip() or f"disclosure hygiene exited {completed.returncode}"
        raise RuntimeError(f"player disclosure hygiene failed: {detail}")


def copy_frontend_ui_dist(frontend_dist_dir: Path, dest_dir: Path) -> dict[str, object]:
    frontend_dist_dir = frontend_dist_dir.resolve()
    if not frontend_dist_dir.exists():
        raise ValueError(
            f"frontend dist path does not exist: {frontend_dist_dir}. "
            "Run the frontend production build first or pass --no-frontend-ui for a backend-only candidate."
        )
    if not frontend_dist_dir.is_dir():
        raise ValueError(f"frontend dist path is not a directory: {frontend_dist_dir}")
    validate_frontend_dist(frontend_dist_dir)
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    for source in iter_allowed_frontend_dist_files(frontend_dist_dir):
        relative = source.relative_to(frontend_dist_dir)
        copy_file(source, dest_dir / relative)
    files = inventory(dest_dir)
    return {
        "artifact_class": "runtime-dist",
        "delivery_path": "ui/",
        "file_count": len(files),
        "source": str(frontend_dist_dir),
    }


def validate_frontend_dist(frontend_dist_dir: Path) -> None:
    missing = [name for name in FRONTEND_DIST_REQUIRED_FILES if not (frontend_dist_dir / name).is_file()]
    if missing:
        raise ValueError(f"frontend dist is missing required runtime files: {', '.join(missing)}")

    for source in frontend_dist_dir.rglob("*"):
        relative = source.relative_to(frontend_dist_dir)
        if is_forbidden_frontend_dist_path(relative):
            raise ValueError(f"frontend dist contains non-participant artifact: {relative.as_posix()}")


def iter_allowed_frontend_dist_files(frontend_dist_dir: Path) -> Iterable[Path]:
    for source in sorted(frontend_dist_dir.rglob("*"), key=lambda item: item.relative_to(frontend_dist_dir).as_posix()):
        if source.is_file():
            yield source


def is_forbidden_frontend_dist_path(relative: Path) -> bool:
    parts = relative.parts
    if any(part in FRONTEND_DIST_FORBIDDEN_DIR_NAMES for part in parts[:-1]):
        return True
    name = relative.name
    lowered = name.lower()
    return lowered in FRONTEND_DIST_FORBIDDEN_FILE_NAMES or any(lowered.endswith(suffix) for suffix in FRONTEND_DIST_FORBIDDEN_SUFFIXES)


def copy_tree(source_dir: Path, dest_dir: Path) -> None:
    for source in iter_allowed_files(source_dir):
        relative = source.relative_to(source_dir)
        repo_relative = source.relative_to(ROOT)
        if should_omit_player_source(repo_relative):
            continue
        copy_file(source, dest_dir / sanitize_candidate_relative_path(repo_relative, relative))


def copy_vendor_tree(source_dir: Path, dest_dir: Path) -> None:
    for source in iter_allowed_vendor_files(source_dir):
        relative = source.relative_to(source_dir)
        dest = dest_dir / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)


def copy_migration_command(output_dir: Path) -> None:
    copy_file(ROOT / "scripts" / "migrate" / "main.go", output_dir / "cmd" / "aml-migrate" / "main.go")


def iter_allowed_files(source_dir: Path) -> Iterable[Path]:
    for source in sorted(source_dir.rglob("*"), key=lambda item: item.relative_to(source_dir).as_posix()):
        if not source.is_file():
            continue
        relative = source.relative_to(source_dir)
        if should_exclude(relative):
            continue
        yield source


def iter_allowed_vendor_files(source_dir: Path) -> Iterable[Path]:
    for source in sorted(source_dir.rglob("*"), key=lambda item: item.relative_to(source_dir).as_posix()):
        if not source.is_file():
            continue
        relative = source.relative_to(source_dir)
        if should_exclude(relative):
            continue
        if source.name == "modules.txt" or source.suffix.lower() in VENDOR_FILE_ALLOW_SUFFIXES:
            yield source


def should_exclude(relative: Path) -> bool:
    parts = relative.parts
    if any(part in EXCLUDED_DIR_NAMES for part in parts[:-1]):
        return True
    name = relative.name
    lowered = name.lower()
    return (
        name.endswith("_test.go")
        or relative.suffix.lower() in EXCLUDED_FILE_SUFFIXES
        or any(lowered.endswith(suffix) for suffix in EXCLUDED_FILE_SUFFIX_CHAINS)
    )


def copy_file(source: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if source.suffix == ".go":
        dest.write_text(sanitize_go_source(source.read_text(encoding="utf-8")), encoding="utf-8", newline="\n")
        return
    shutil.copyfile(source, dest)


def should_omit_player_source(repo_relative: Path) -> bool:
    return repo_relative.as_posix() in PLAYER_SOURCE_OMIT_PATHS


def sanitize_candidate_relative_path(repo_relative: Path, relative: Path) -> Path:
    mapped = PLAYER_SOURCE_RENAMES.get(repo_relative.as_posix())
    if mapped is not None:
        mapped_relative = Path(mapped)
        return Path(*mapped_relative.parts[1:])
    parts = list(relative.parts)
    if relative.suffix == ".go":
        parts[-1] = parts[-1].replace("_profile_", "_policy_")
        parts[-1] = parts[-1].replace("profile_", "policy_")
        parts[-1] = parts[-1].replace("_profile.go", "_policy.go")
    return Path(*parts)


def sanitize_go_source(text: str) -> str:
    sanitized = strip_go_build_constraints(text)
    sanitized = sanitize_api_entrypoint_args(sanitized)
    sanitized = sanitize_worker_entrypoint_args(sanitized)
    for tag in LEGACY_PROFILE_TAGS:
        sanitized = sanitized.replace(f" || {tag}", "")
        sanitized = sanitized.replace(f" && !{tag}", "")
    for old, new in SOURCE_TOKEN_REPLACEMENTS.items():
        sanitized = sanitized.replace(old, new)
    return sanitized


def strip_go_build_constraints(text: str) -> str:
    return re.sub(r"\A//go:build[^\n]*\n(?:// \+build[^\n]*\n)?\n?", "", text)


def sanitize_api_entrypoint_args(text: str) -> str:
    if 'addr := flag.String("addr", ":8080", "HTTP listen address")' not in text:
        return text

    sanitized = text.replace('\t"flag"\n', "")
    sanitized = sanitized.replace('\t"os/signal"\n', '\t"os/signal"\n\t"strings"\n')
    sanitized = sanitized.replace(
        "func main() {\n"
        '\taddr := flag.String("addr", ":8080", "HTTP listen address")\n'
        "\tflag.Parse()\n",
        "func listenAddressFromArgs(args []string) string {\n"
        '\taddr := ":8080"\n'
        "\tfor i := 0; i < len(args); i++ {\n"
        '\t\tif args[i] == "-addr" && i+1 < len(args) {\n'
        "\t\t\taddr = args[i+1]\n"
        "\t\t\ti++\n"
        "\t\t\tcontinue\n"
        "\t\t}\n"
        '\t\tif strings.HasPrefix(args[i], "-addr=") {\n'
        '\t\t\taddr = strings.TrimPrefix(args[i], "-addr=")\n'
        "\t\t}\n"
        "\t}\n"
        "\treturn addr\n"
        "}\n\n"
        "func main() {\n"
        "\taddr := listenAddressFromArgs(os.Args[1:])\n",
    )
    sanitized = sanitized.replace("Addr:              *addr,", "Addr:              addr,")
    sanitized = sanitized.replace('logger.Info("aml-api listening", "addr", *addr)', 'logger.Info("aml-api listening", "addr", addr)')
    return sanitized


def sanitize_worker_entrypoint_args(text: str) -> str:
    if 'once := flag.Bool("once", false, "run one deterministic worker scan and exit")' not in text:
        return text

    sanitized = text.replace('\t"flag"\n', "")
    sanitized = sanitized.replace('\t"os/signal"\n', '\t"os/signal"\n\t"strings"\n')
    sanitized = sanitized.replace(
        "func main() {\n"
        "\tcfg := workerConfigFromEnv()\n"
        '\tonce := flag.Bool("once", false, "run one deterministic worker scan and exit")\n'
        '\tinterval := flag.Duration("interval", cfg.ScanInterval, "network-room scan interval")\n'
        "\tflag.Parse()\n",
        "func workerOptionsFromArgs(args []string, cfg workerConfig) (workerConfig, bool) {\n"
        "\tonce := false\n"
        "\tfor i := 0; i < len(args); i++ {\n"
        "\t\tswitch {\n"
        '\t\tcase args[i] == "-once":\n'
        "\t\t\tonce = true\n"
        '\t\tcase args[i] == "-interval" && i+1 < len(args):\n'
        "\t\t\tif parsed, err := time.ParseDuration(args[i+1]); err == nil {\n"
        "\t\t\t\tcfg.ScanInterval = parsed\n"
        "\t\t\t}\n"
        "\t\t\ti++\n"
        '\t\tcase strings.HasPrefix(args[i], "-interval="):\n'
        '\t\t\tif parsed, err := time.ParseDuration(strings.TrimPrefix(args[i], "-interval=")); err == nil {\n'
        "\t\t\t\tcfg.ScanInterval = parsed\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t}\n"
        "\treturn cfg, once\n"
        "}\n\n"
        "func main() {\n"
        "\tcfg, once := workerOptionsFromArgs(os.Args[1:], workerConfigFromEnv())\n",
    )
    sanitized = sanitized.replace("\tcfg.ScanInterval = *interval\n\n", "\n")
    sanitized = sanitized.replace("run(ctx, logger, repo, cfg, *once)", "run(ctx, logger, repo, cfg, once)")
    sanitized = sanitized.replace("run(ctx, logger, networkroom.NewRepository(database), *interval, *once)", "run(ctx, logger, networkroom.NewRepository(database), interval, once)")
    return sanitized


def player_hygiene_allowlist() -> dict[str, list[dict[str, object]]]:
    return {"allow": []}


def inventory(root: Path) -> list[str]:
    return sorted(str(path.relative_to(root)).replace("\\", "/") for path in root.rglob("*") if path.is_file())


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(os.environ.get("SENTINEL_AML_PLAYER_CANDIDATE", DEFAULT_OUTPUT_DIR)),
    )
    parser.add_argument("--allowlist-out", type=Path)
    parser.add_argument(
        "--frontend-dist-dir",
        type=Path,
        default=Path(os.environ.get("SENTINEL_AML_FRONTEND_DIST", DEFAULT_FRONTEND_DIST_DIR)),
        help="include an already built participant UI dist as ui/ when the directory exists",
    )
    parser.add_argument(
        "--no-frontend-ui",
        action="store_true",
        help="do not include a participant UI runtime dist even if frontend/dist exists",
    )
    parser.add_argument(
        "--stub",
        action="store_true",
        help="build the minimal W33-T02 smoke candidate instead of the source candidate",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.stub:
            result = build_stub_player_candidate(args.output_dir)
        else:
            frontend_dist_dir = None if args.no_frontend_ui else args.frontend_dist_dir
            result = build_player_candidate(
                args.output_dir,
                args.allowlist_out,
                frontend_dist_dir,
                require_participant_ui=not args.no_frontend_ui,
            )
    except Exception as exc:
        result = {
            "status": "fail",
            "candidate_type": "player-service",
            "output_dir": str(args.output_dir),
            "message": str(exc),
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
