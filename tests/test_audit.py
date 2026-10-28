import os
import sys
import json
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from prompts import REPORT_CONFIG, SYSTEM_PROMPT, SBOM_PROMPT, CBOM_PROMPT
from ingest import collect_files, LANG_MAP
from ci_security_audit import extract_sbom_deterministic, extract_cbom_deterministic, run_ci_audit

def test_prompts_configuration():
    """Verify REPORT_CONFIG contains all expected audit categories with valid prompts."""
    required_categories = ["sbom", "cbom", "rca", "gap_analysis"]
    for cat in required_categories:
        assert cat in REPORT_CONFIG, f"Category '{cat}' missing from REPORT_CONFIG"
        config = REPORT_CONFIG[cat]
        assert "title" in config
        assert "prompt_template" in config
        assert "queries" in config
        assert isinstance(config["queries"], list)
        assert len(config["queries"]) > 0
        assert "top_k" in config
        assert "{context}" in config["prompt_template"], f"Missing {{context}} placeholder in {cat} prompt"

def test_ingest_collect_files():
    """Verify collect_files collects appropriate repository files while ignoring vendor/cache dirs."""
    repo_path = Path(__file__).resolve().parent.parent
    files = collect_files(str(repo_path))
    filenames = [f.name for f in files]

    # Must contain essential code files
    assert "agent.py" in filenames
    assert "app.py" in filenames
    assert "ingest.py" in filenames
    assert "prompts.py" in filenames
    assert "requirements.txt" in filenames

    # Must not contain excluded directories or cache files
    for f in files:
        parts = f.parts
        assert ".git" not in parts
        assert "__pycache__" not in parts
        assert ".venv" not in parts
        assert "node_modules" not in parts

def test_deterministic_sbom_extraction():
    """Verify deterministic SBOM extraction correctly parses requirements.txt and imports."""
    repo_path = Path(__file__).resolve().parent.parent
    sbom = extract_sbom_deterministic(repo_path)

    assert sbom["category"] == "sbom"
    assert sbom["total"] > 0
    assert "table" in sbom
    assert "summary" in sbom
    assert "| Component | Version | Ecosystem |" in sbom["table"]

    # Verify key packages are present
    component_names = [c["component"] for c in sbom["items"]]
    assert "streamlit" in component_names
    assert "langchain" in component_names
    assert "qdrant-client" in component_names

def test_deterministic_cbom_extraction():
    """Verify deterministic CBOM extraction detects crypto primitives in code."""
    repo_path = Path(__file__).resolve().parent.parent
    cbom = extract_cbom_deterministic(repo_path)

    assert cbom["category"] == "cbom"
    assert cbom["total"] > 0
    assert "table" in cbom
    assert "summary" in cbom
    assert "| Asset | Algorithm / Primitive |" in cbom["table"]

    asset_names = [a["asset"] for a in cbom["items"]]
    # ingest.py uses MD5 and Cosine similarity
    assert "MD5" in asset_names or "Cosine Similarity" in asset_names

def test_ci_security_audit_runner(tmp_path):
    """Verify run_ci_audit runs successfully and generates report files."""
    out_dir = tmp_path / "test_reports"
    exit_code = run_ci_audit(fail_on_critical=False, output_dir=str(out_dir))

    assert exit_code == 0
    generated_files = list(out_dir.glob("audit_sbom_cbom_*"))
    assert len(generated_files) >= 2  # .md and .json

    md_file = [f for f in generated_files if f.suffix == ".md"][0]
    json_file = [f for f in generated_files if f.suffix == ".json"][0]

    md_text = md_file.read_text(encoding="utf-8")
    assert "Software Bill of Materials (SBOM)" in md_text
    assert "Cryptography Bill of Materials (CBOM)" in md_text

    data = json.loads(json_file.read_text(encoding="utf-8"))
    assert "sbom" in data
    assert "cbom" in data
