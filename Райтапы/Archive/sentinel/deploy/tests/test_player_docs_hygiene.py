from __future__ import annotations

import gzip
import importlib.util
import io
import re
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_ROOT = ROOT / "packaging" / "player_templates"
DOC_PATHS = (
    Path("README.md"),
    Path("TROUBLESHOOTING.md"),
    Path("Makefile"),
    Path("tests/public_smoke/public_smoke.py"),
)
FORBIDDEN_PATTERNS = {
    "ctf": re.compile(r"\bctf\b", re.IGNORECASE),
    "checker": re.compile(r"\bchecker\b", re.IGNORECASE),
    "flag": re.compile(r"\bflags?\b", re.IGNORECASE),
    "sploit": re.compile(r"\bsploits?\b", re.IGNORECASE),
    "exploit": re.compile(r"\bexploits?\b", re.IGNORECASE),
    "fix": re.compile(r"\bfix(?:es|ed|ing)?\b", re.IGNORECASE),
    "vulnerability": re.compile(r"\bvulnerabilit(?:y|ies)\b", re.IGNORECASE),
    "vulnerable": re.compile(r"\bvulnerable\b", re.IGNORECASE),
    "wave": re.compile(r"\bwaves?\b", re.IGNORECASE),
    "organizer": re.compile(r"\borganizers?\b", re.IGNORECASE),
    "architecture docs": re.compile(r"\barchitecture docs?\b", re.IGNORECASE),
    "reference evidence": re.compile(r"\breference evidence\b", re.IGNORECASE),
    "build profile": re.compile(r"\bbuild profiles?\b", re.IGNORECASE),
    "secret": re.compile(r"\bsecrets?\b", re.IGNORECASE),
    "credential": re.compile(r"\bcredentials?\b", re.IGNORECASE),
    "hidden endpoint": re.compile(r"\bhidden endpoints?\b", re.IGNORECASE),
    "debug route": re.compile(r"\bdebug routes?\b", re.IGNORECASE),
}


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


builder = load_script("build_player_source_artifact", ROOT / "scripts" / "build_player_source_artifact.py")


class PlayerDocsHygieneTest(unittest.TestCase):
    def test_player_templates_do_not_use_forbidden_words(self):
        findings = scan_texts({path.as_posix(): (TEMPLATE_ROOT / path).read_text(encoding="utf-8") for path in DOC_PATHS})

        self.assertEqual(findings, [])

    def test_generated_artifact_docs_match_templates_and_stay_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sentinel-aml-player-source.tar.gz"
            result = builder.build_player_source_artifact(artifact)
            self.assertEqual(result["status"], "pass", result)
            docs = artifact_docs(artifact)

        self.assertEqual(set(docs), {path.as_posix() for path in DOC_PATHS})
        self.assertEqual(scan_texts(docs), [])
        self.assertIn("docker compose up --build", docs["README.md"])
        self.assertIn("make rebuild", docs["README.md"])
        self.assertIn("make smoke", docs["README.md"])
        self.assertIn("healthz", docs["tests/public_smoke/public_smoke.py"])
        self.assertIn("readyz", docs["tests/public_smoke/public_smoke.py"])


def artifact_docs(artifact: Path) -> dict[str, str]:
    with gzip.open(artifact, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        docs: dict[str, str] = {}
        for path in DOC_PATHS:
            member_name = f"{builder.ARCHIVE_ROOT}/{path.as_posix()}"
            handle = archive.extractfile(member_name)
            assert handle is not None
            docs[path.as_posix()] = handle.read().decode("utf-8")
        return docs


def scan_texts(texts: dict[str, str]) -> list[tuple[str, int, str, str]]:
    findings: list[tuple[str, int, str, str]] = []
    for path, text in sorted(texts.items()):
        for line_no, line in enumerate(text.splitlines(), start=1):
            for label, pattern in FORBIDDEN_PATTERNS.items():
                if pattern.search(line):
                    findings.append((path, line_no, label, line.strip()))
    return findings


if __name__ == "__main__":
    unittest.main()
