#!/usr/bin/env python3
"""Build the flattened Sentinel AML player source artifact."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Iterable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_frontend_static_dist


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_ROOT = "sentinel-aml-player-source"
DEFAULT_OUTPUT = ROOT / "out" / "artifacts" / "sentinel-aml-player-source.tar.gz"
TEMPLATE_ROOT = ROOT / "packaging" / "player_templates"
MANIFEST_NAME = "PLAYER_SOURCE_MANIFEST.json"
CHECKSUM_NAME = "SHA256SUMS"
BUILDER_VERSION = "w35-p01-backend-source-static-ui.v1"
SOURCE_GENERATION_TIMESTAMP = "1970-01-01T00:00:00Z"
FIXED_MTIME = 0

ROOT_SOURCE_FILES = ("go.mod", "go.sum")
SOURCE_DIRS = ("cmd", "internal", "migrations", "vendor")
FRONTEND_STATIC_DIR = ROOT / "out" / "frontend-dist"
FRONTEND_STATIC_STAGE = Path("web/dist")
GENERATED_FILES = {
    "README.md",
    "TROUBLESHOOTING.md",
    "Makefile",
    "Dockerfile",
    "PACKAGE_MANIFEST.json",
    "cmd/aml-migrate/main.go",
    "docker-compose.yml",
    "deploy/player.env.example",
}
EXCLUDED_CATEGORIES = {
    "organizer_only": ["checkers/", "sploits/", "exploits/", "fixes/", "docs/", "validation/"],
    "generated_or_cache": ["out/", "tmp/", "frontend/node_modules/", "frontend/dist/", "__pycache__/"],
    "frontend_source": ["frontend/src/", "frontend/package*.json", "frontend/vite.config.*", "frontend/tsconfig*.json"],
    "developer_tests": ["repository test suites", "frontend/tests/", "frontend/e2e/", "*_test.go"],
    "profile_pairs": ["*_secure.go", "*_vulnerable.go", "*_default.go", "*_detail.go", "*_profile_*.go"],
}
EXCLUDED_DIR_NAMES = {
    ".git",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".vscode",
    "__pycache__",
    "node_modules",
    "dist",
    "e2e",
    "tests",
    "playwright-report",
    "test-results",
}
EXCLUDED_SUFFIXES = {
    ".coverprofile",
    ".exe",
    ".map",
    ".pyc",
    ".pyo",
    ".tar",
    ".test",
    ".tgz",
    ".tsbuildinfo",
    ".zip",
}
POSITIVE_BUILD_TAGS = {
    "case_match_preview",
    "audit_detail_view",
    "entity_review_summary",
    "linked_case_export_detail",
    "network_room_detail",
    "aml1_vulnerable",
    "aml2_vulnerable",
    "aml3_vulnerable",
    "aml4_vulnerable",
    "aml5_vulnerable",
}
REVEALING_TEXT_REPLACEMENTS = {
    "caseMatchPreviewProfileEnabled": "caseMatchPreviewAvailable",
    "auditDetailProfileEnabled": "auditActivityViewsAvailable",
    "entityReviewSummaryProfileEnabled": "entityReviewSummariesAvailable",
    "linkedCaseExportProfileEnabled": "linkedCaseExportAvailable",
    "networkRoomDetailProfileEnabled": "networkRoomContextAvailable",
    "caseAuditViewsForProfile": "caseAuditViewsForActivityStream",
    "entityActivityViewsForProfile": "entityActivityViewsForActivityStream",
    "graphEDDSummariesResponseForProfile": "graphEDDSummariesResponseForEntityReview",
    "networkRoomDossierResponseForProfile": "networkRoomDossierResponseForSharedRoom",
    "populateExportLinkedCaseProfileData": "populateExportLinkedCaseData",
    "appendExportProfileData": "appendExportLinkedCaseData",
    "cloneExportProfileMaps": "cloneExportLinkedEvidenceMaps",
}
GO_FILE_RENAMES = {
    "internal/exporting/export_profile_linked_case.go": "internal/exporting/export_linked_evidence.go",
    "internal/graph/repository_entity_review.go": "internal/graph/repository_entity_summaries.go",
    "internal/httpapi/audit_profile_detail.go": "internal/httpapi/activity_views.go",
    "internal/httpapi/dedup_profile_case_match.go": "internal/httpapi/dedup_merge_preview.go",
    "internal/httpapi/export_profile_linked_case.go": "internal/httpapi/export_linked_cases.go",
    "internal/httpapi/graph_profile_entity_review.go": "internal/httpapi/entity_review_summaries.go",
    "internal/httpapi/network_room_profile_detail.go": "internal/httpapi/network_room_context.go",
    "internal/networkroom/dossier_profile_room_detail.go": "internal/networkroom/dossier_context.go",
    "internal/networkroom/repository_room_detail.go": "internal/networkroom/repository_context.go",
}


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    output = args.output.resolve()
    try:
        result = build_player_source_artifact(output)
    except Exception as exc:
        print(json.dumps({"status": "fail", "message": str(exc)}, indent=2, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args(argv)


def build_player_source_artifact(output: Path) -> dict[str, object]:
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest_path = output.parent / MANIFEST_NAME
    checksum_path = output.parent / CHECKSUM_NAME

    with tempfile.TemporaryDirectory(prefix="sentinel-aml-player-source-") as tmp:
        stage = Path(tmp) / ARCHIVE_ROOT
        stage.mkdir(parents=True)
        copy_player_sources(stage)
        frontend_static = copy_frontend_static_bundle(stage)
        write_generated_player_docs(stage)
        files = inventory(stage)
        archive_entries = write_archive(stage, output, files)
        backend_source_file_count = len(
            [
                relative
                for relative in files
                if relative.parts and relative.parts[0] in {"cmd", "internal", "migrations", "vendor"} or relative.as_posix() in ROOT_SOURCE_FILES
            ]
        )

    artifact_sha = sha256_file(output)
    manifest = {
        "schema": "sentinel-aml-player-source-manifest.v1",
        "builder": {
            "name": "scripts/build_player_source_artifact.py",
            "version": BUILDER_VERSION,
        },
        "artifact": {
            "path": output.as_posix(),
            "sha256": artifact_sha,
            "archive_root": ARCHIVE_ROOT,
            "file_count": len(archive_entries),
            "primary_player_artifact": True,
            "distribution_model": "backend-source-static-frontend-player",
            "flattened_competition_tree": True,
            "backend_source_file_count": backend_source_file_count,
            "frontend_static_sha256": frontend_static["sha256"],
            "frontend_dist_file_count": frontend_static["file_count"],
        },
        "source_generation_timestamp": SOURCE_GENERATION_TIMESTAMP,
        "frontend_static": frontend_static,
        "included_roots": sorted([*ROOT_SOURCE_FILES, *SOURCE_DIRS, "web/dist", *GENERATED_FILES]),
        "excluded_categories": EXCLUDED_CATEGORIES,
        "files": archive_entries,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    checksum_path.write_text(
        f"{artifact_sha}  {output.name}\n{sha256_file(manifest_path)}  {manifest_path.name}\n",
        encoding="utf-8",
        newline="\n",
    )
    return {
        "status": "pass",
        "artifact": output.as_posix(),
        "sha256": artifact_sha,
        "file_count": len(archive_entries),
        "manifest": manifest_path.as_posix(),
        "checksums": checksum_path.as_posix(),
        "flattened": True,
    }


def copy_player_sources(stage: Path) -> None:
    for relative in ROOT_SOURCE_FILES:
        copy_source_file(ROOT / relative, stage / relative, Path(relative))
    for dirname in SOURCE_DIRS:
        source_dir = ROOT / dirname
        if not source_dir.exists():
            if dirname == "vendor":
                continue
            raise FileNotFoundError(f"required source directory missing: {dirname}")
        for source in iter_source_files(source_dir):
            relative = source.relative_to(ROOT)
            destination_relative = staged_relative_path(relative)
            copy_source_file(source, stage / destination_relative, relative)


def copy_frontend_static_bundle(stage: Path) -> dict[str, object]:
    if not (FRONTEND_STATIC_DIR / "index.html").is_file():
        build_frontend_static_dist.build_frontend_static_dist(
            FRONTEND_STATIC_DIR,
            run_npm=not (ROOT / "frontend" / "dist" / "index.html").is_file(),
        )
    else:
        build_frontend_static_dist.validate_frontend_dist(FRONTEND_STATIC_DIR)
    destination_root = stage / FRONTEND_STATIC_STAGE
    files: list[Path] = []
    for source in build_frontend_static_dist.iter_static_files(FRONTEND_STATIC_DIR):
        relative = source.relative_to(FRONTEND_STATIC_DIR)
        destination = destination_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        files.append(relative)
    return {
        "source": FRONTEND_STATIC_DIR.as_posix(),
        "delivery_path": FRONTEND_STATIC_STAGE.as_posix(),
        "sha256": build_frontend_static_dist.sha256_tree(FRONTEND_STATIC_DIR),
        "file_count": len(files),
    }


def iter_source_files(source_dir: Path) -> Iterable[Path]:
    for source in sorted(source_dir.rglob("*"), key=lambda item: item.relative_to(ROOT).as_posix()):
        if not source.is_file():
            continue
        relative = source.relative_to(ROOT)
        if should_exclude(relative):
            continue
        if relative.parts[0] != "vendor" and source.suffix == ".go" and not should_include_go_source(source):
            continue
        yield source


def should_exclude(relative: Path) -> bool:
    path = relative.as_posix()
    parts = relative.parts
    name = relative.name
    lowered = name.lower()
    if name.endswith("_test.go"):
        return True
    if any(part in EXCLUDED_DIR_NAMES for part in parts[:-1]):
        return True
    if lowered.endswith(tuple(EXCLUDED_SUFFIXES)):
        return True
    if path in {
        "frontend/README.md",
        "frontend/playwright.config.ts",
        "frontend/tsconfig.app.tsbuildinfo",
        "frontend/tsconfig.node.tsbuildinfo",
    }:
        return True
    if path.startswith("frontend/scripts/"):
        return True
    return False


def should_include_go_source(source: Path) -> bool:
    text = source.read_text(encoding="utf-8")
    build_expr = first_build_expr(text)
    if build_expr is None:
        return True
    tokens = set(re.findall(r"[A-Za-z0-9_]+", build_expr))
    if tokens & POSITIVE_BUILD_TAGS and "!" not in build_expr:
        return True
    return False


def first_build_expr(text: str) -> str | None:
    match = re.match(r"//go:build\s+(.+)", text)
    return match.group(1).strip() if match else None


def staged_relative_path(relative: Path) -> Path:
    if relative.parts[0] == "vendor":
        return relative
    mapped = GO_FILE_RENAMES.get(relative.as_posix())
    if mapped is not None:
        return Path(mapped)
    name = relative.name
    if relative.suffix == ".go":
        name = name.replace("_profile_", "_")
        name = name.replace("profile_", "")
        name = name.replace("_detail.go", "_context.go")
        name = name.replace("_default.go", ".go")
        name = name.replace("_secure.go", ".go")
        name = name.replace("_vulnerable.go", ".go")
        return relative.with_name(name)
    return relative


def copy_source_file(source: Path, destination: Path, relative: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if relative.parts[0] != "vendor" and source.suffix == ".go":
        destination.write_text(sanitize_go_source(source.read_text(encoding="utf-8")), encoding="utf-8", newline="\n")
        return
    shutil.copyfile(source, destination)


def sanitize_go_source(text: str) -> str:
    sanitized = strip_build_constraints(text)
    for old, new in REVEALING_TEXT_REPLACEMENTS.items():
        sanitized = sanitized.replace(old, new)
    for tag in POSITIVE_BUILD_TAGS:
        sanitized = sanitized.replace(tag, "")
    return sanitized


def strip_build_constraints(text: str) -> str:
    return re.sub(r"\A//go:build[^\n]*\n(?:// \+build[^\n]*\n)?\n?", "", text)


def write_generated_player_docs(stage: Path) -> None:
    files = {
        "README.md": template_text("README.md"),
        "TROUBLESHOOTING.md": template_text("TROUBLESHOOTING.md"),
        "Makefile": template_text("Makefile"),
        "PACKAGE_MANIFEST.json": player_package_manifest(),
        "Dockerfile": PLAYER_DOCKERFILE,
        "cmd/aml-migrate/main.go": PLAYER_MIGRATE_MAIN,
        "docker-compose.yml": PLAYER_COMPOSE,
        "deploy/player.env.example": PLAYER_ENV_EXAMPLE,
    }
    for relative, content in files.items():
        path = stage / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")


def template_text(relative: str) -> str:
    path = TEMPLATE_ROOT / relative
    if not path.is_file():
        raise FileNotFoundError(f"required player template missing: {path.relative_to(ROOT).as_posix()}")
    text = path.read_text(encoding="utf-8")
    return text if text.endswith("\n") else text + "\n"


def player_package_manifest() -> str:
    manifest = {
        "artifact_class": "player-source",
        "artifact_contract": "backend-source-static-frontend-player-distribution.v1",
        "primary_player_artifact": True,
        "distribution_model": "backend-source-static-frontend-player",
        "archive_name": "sentinel-aml-player-source.tar.gz",
        "admin_organizer_separate": True,
        "runtime_requirements": {
            "go": "1.22+",
            "postgres": "16 compatible",
        },
        "build_commands": [
            "go test ./...",
            "go build ./cmd/aml-api ./cmd/aml-worker ./cmd/aml-migrate",
        ],
        "frontend_static": {
            "included": True,
            "path": "web/dist",
            "source_included": False,
        },
    }
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def inventory(root: Path) -> list[Path]:
    return sorted((path.relative_to(root) for path in root.rglob("*") if path.is_file()), key=lambda item: item.as_posix())


def write_archive(stage: Path, output: Path, files: list[Path]) -> list[dict[str, object]]:
    payload = io.BytesIO()
    entries: list[dict[str, object]] = []
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for relative in files:
            source = stage / relative
            member_name = f"{ARCHIVE_ROOT}/{relative.as_posix()}"
            info = archive.gettarinfo(str(source), arcname=member_name)
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = FIXED_MTIME
            info.mode = 0o644
            digest = sha256_file(source)
            with source.open("rb") as handle:
                archive.addfile(info, handle)
            entries.append({"path": member_name, "sha256": digest, "size_bytes": source.stat().st_size})
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=FIXED_MTIME) as gz:
            gz.write(payload.getvalue())
    return entries


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


PLAYER_DOCKERFILE = """FROM golang:1.22-alpine AS go-build
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations
RUN GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go build -o /out/aml-api ./cmd/aml-api
RUN GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go build -o /out/aml-worker ./cmd/aml-worker
RUN GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go build -o /out/aml-migrate ./cmd/aml-migrate

FROM alpine:3.20 AS runtime
WORKDIR /app
COPY --from=go-build /out/aml-api /app/aml-api
COPY --from=go-build /out/aml-worker /app/aml-worker
COPY --from=go-build /out/aml-migrate /app/aml-migrate
COPY --from=go-build /src/migrations /app/migrations
EXPOSE 8080
CMD ["/app/aml-api", "-addr", ":8080"]

FROM nginx:1.27-alpine AS ui
COPY web/dist /usr/share/nginx/html
RUN printf '%s\\n' 'window.__SENTINEL_CONFIG__ = { apiBaseUrl: "" };' > /usr/share/nginx/html/runtime-config.js \
    && printf '%s\\n' \
      'server {' \
      '  listen 80;' \
      '  server_name _;' \
      '  root /usr/share/nginx/html;' \
      '  index index.html;' \
      '  location /api/ { proxy_pass http://aml-api:8080; }' \
      '  location /healthz { proxy_pass http://aml-api:8080; }' \
      '  location /readyz { proxy_pass http://aml-api:8080; }' \
      '  location / { try_files $uri $uri/ /index.html; }' \
      '}' > /etc/nginx/conf.d/default.conf
"""

PLAYER_MIGRATE_MAIN = """package main

import (
\t"context"
\t"log/slog"
\t"os"

\t"sentinel-aml/internal/config"
\t"sentinel-aml/internal/db"
)

func main() {
\tlogger := slog.New(slog.NewTextHandler(os.Stdout, nil))
\tctx := context.Background()

\tdatabase, err := db.Open(ctx, config.DatabaseFromEnv())
\tif err != nil {
\t\tlogger.Error("open database failed", "error", err)
\t\tos.Exit(1)
\t}
\tdefer func() {
\t\tif err := db.Close(database); err != nil {
\t\t\tlogger.Error("close database failed", "error", err)
\t\t}
\t}()

\tmigrations, err := db.LoadMigrations("migrations")
\tif err != nil {
\t\tlogger.Error("load migrations failed", "error", err)
\t\tos.Exit(1)
\t}

\tif err := db.ApplyMigrations(ctx, database, migrations); err != nil {
\t\tlogger.Error("apply migrations failed", "error", err)
\t\tos.Exit(1)
\t}

\tlogger.Info("migrations applied", "count", len(migrations))
}
"""

PLAYER_COMPOSE = """services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: sentinel_aml
      POSTGRES_USER: sentinel
      POSTGRES_PASSWORD: sentinel
    volumes:
      - sentinel_aml_pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sentinel -d sentinel_aml"]
      interval: 2s
      timeout: 5s
      retries: 20

  aml-migrate:
    build:
      context: .
      target: runtime
    command: ["/app/aml-migrate"]
    environment:
      DATABASE_URL: postgres://sentinel:sentinel@postgres:5432/sentinel_aml?sslmode=disable
    depends_on:
      postgres:
        condition: service_healthy

  aml-api:
    build:
      context: .
      target: runtime
    command: ["/app/aml-api", "-addr", ":8080"]
    environment:
      DATABASE_URL: postgres://sentinel:sentinel@postgres:5432/sentinel_aml?sslmode=disable
    depends_on:
      aml-migrate:
        condition: service_completed_successfully
    ports:
      - "${SENTINEL_AML_API_PORT:-8080}:8080"

  aml-worker:
    build:
      context: .
      target: runtime
    command: ["/app/aml-worker"]
    environment:
      DATABASE_URL: postgres://sentinel:sentinel@postgres:5432/sentinel_aml?sslmode=disable
      NETWORK_ROOM_BATCH_SIZE: "${NETWORK_ROOM_BATCH_SIZE:-100}"
      NETWORK_ROOM_LOCK_TTL_SECONDS: "${NETWORK_ROOM_LOCK_TTL_SECONDS:-30}"
      NETWORK_ROOM_WORKER_TIMEOUT_MS: "${NETWORK_ROOM_WORKER_TIMEOUT_MS:-5000}"
      NETWORK_ROOM_SCAN_INTERVAL_SECONDS: "${NETWORK_ROOM_SCAN_INTERVAL_SECONDS:-5}"
      NETWORK_ROOM_CASE_LIMIT_PER_CANDIDATE: "${NETWORK_ROOM_CASE_LIMIT_PER_CANDIDATE:-500}"
      NETWORK_ROOM_ARTIFACT_LIMIT_PER_CASE: "${NETWORK_ROOM_ARTIFACT_LIMIT_PER_CASE:-20}"
    depends_on:
      aml-migrate:
        condition: service_completed_successfully

  aml-ui:
    build:
      context: .
      target: ui
    depends_on:
      aml-api:
        condition: service_started
    ports:
      - "${SENTINEL_AML_HTTP_PORT:-8081}:80"

volumes:
  sentinel_aml_pgdata:
"""

PLAYER_ENV_EXAMPLE = """DATABASE_URL=postgres://sentinel:sentinel@postgres:5432/sentinel_aml?sslmode=disable
SENTINEL_AML_API_PORT=8080
SENTINEL_AML_HTTP_PORT=8081
NETWORK_ROOM_BATCH_SIZE=100
NETWORK_ROOM_LOCK_TTL_SECONDS=30
NETWORK_ROOM_WORKER_TIMEOUT_MS=5000
NETWORK_ROOM_SCAN_INTERVAL_SECONDS=5
NETWORK_ROOM_CASE_LIMIT_PER_CANDIDATE=500
NETWORK_ROOM_ARTIFACT_LIMIT_PER_CASE=20
"""


if __name__ == "__main__":
    raise SystemExit(main())
