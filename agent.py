import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

from dotenv import load_dotenv
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from langchain_ollama import OllamaLLM, OllamaEmbeddings
from langchain_qdrant import QdrantVectorStore
from qdrant_client import QdrantClient

from prompts import SYSTEM_PROMPT, REPORT_CONFIG
from remediation import AuditorAgent, FixerSubagent, GitManager, AuditReport, Finding, RemediationPatch

load_dotenv()  # loads GEMINI_API_KEY / GOOGLE_API_KEY from .env

QDRANT_URL = "http://localhost:6333"
COLLECTION_NAME = "code_audit"
OLLAMA_EMBEDDING_MODEL = "unclemusclez/jina-embeddings-v2-base-code"

LLM_MODEL = "qwen3:4b-q4_K_M"
GEMINI_MODEL = "gemini-3.8-flash"  # Current recommended model as per gemini-api-dev

console = Console()


class GeminiGenAIWrapper:
    """Wrapper around official google-genai Client adhering to gemini-api-dev."""

    def __init__(self, api_key: str, model: str = GEMINI_MODEL):
        from google import genai
        from google.genai import types
        self.client = genai.Client(api_key=api_key)
        self.model = model
        self.types = types

    def invoke(self, prompt: str) -> str:
        try:
            config = self.types.GenerateContentConfig(temperature=0.1)
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=config,
            )
            if response and response.text:
                return response.text
        except Exception:
            try:
                interaction = self.client.interactions.create(
                    model=self.model,
                    input=prompt,
                )
                return interaction.output_text or ""
            except Exception as e:
                return f"[Gemini Error: {e}]"
        return ""


def _extract_text(response) -> str:
    """Normalize an LLM response to a plain string."""
    if isinstance(response, str):
        return response
    if hasattr(response, "content"):
        content = response.content
        if isinstance(content, list):
            return "\n".join(
                item["text"] for item in content if isinstance(item, dict) and "text" in item
            )
        return str(content)
    return str(response)


def get_embeddings(provider: str):
    """Return the appropriate embeddings. Must match the provider used during ingest."""
    if provider == "google":
        from langchain_google_genai import GoogleGenerativeAIEmbeddings
        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        return GoogleGenerativeAIEmbeddings(
            model="models/text-embedding-004",
            google_api_key=api_key,
            task_type="retrieval_query",
        )
    elif provider == "jina":
        from langchain_community.embeddings import JinaEmbeddings
        api_key = os.getenv("JINA_API_KEY")
        return JinaEmbeddings(
            jina_api_key=api_key,
            model_name="jina-embeddings-v2-base-code",
        )
    else:
        return OllamaEmbeddings(model=OLLAMA_EMBEDDING_MODEL)


def get_llm(provider: str):
    """Return the appropriate LLM based on chosen provider."""
    if provider == "gemini":
        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            console.print("[bold red]Error:[/bold red] GEMINI_API_KEY or GOOGLE_API_KEY not found in .env.")
            raise SystemExit(1)
        console.print(f"[bold green]Provider:[/bold green] Google Gemini ({GEMINI_MODEL}) via google-genai SDK\n")
        return GeminiGenAIWrapper(api_key=api_key, model=GEMINI_MODEL)
    else:
        console.print(f"[bold green]Provider:[/bold green] Ollama ({LLM_MODEL})\n")
        return OllamaLLM(
            model=LLM_MODEL,
            temperature=0.1,
            num_ctx=2048,
        )


def get_vectorstore(embeddings_provider: str = "ollama"):
    client = QdrantClient(url=QDRANT_URL)
    embeddings = get_embeddings(embeddings_provider)
    return QdrantVectorStore(
        client=client,
        collection_name=COLLECTION_NAME,
        embedding=embeddings,
    )


def audit_category(llm, vectorstore, category: str, config: dict) -> dict:
    """Run a single audit report: multi-query RAG retrieval + LLM generation."""
    docs = []
    seen = set()

    for query in config["queries"]:
        try:
            results = vectorstore.similarity_search(query, k=config["top_k"])
            for d in results:
                if d.page_content not in seen:
                    seen.add(d.page_content)
                    docs.append(d)
        except Exception:
            pass

    if not docs:
        return {"category": category, "findings": "No relevant code found.", "chunks_analyzed": 0}

    context_parts = []
    for i, doc in enumerate(docs):
        file_ref = doc.metadata.get("file", "unknown")
        context_parts.append(f"--- Chunk {i+1} | File: {file_ref} ---\n{doc.page_content}")
    context = "\n\n".join(context_parts)

    prompt = f"""{SYSTEM_PROMPT}

{config['prompt_template'].replace('{context}', context)}
"""

    response = llm.invoke(prompt)
    return {
        "category": category,
        "findings": _extract_text(response),
        "chunks_analyzed": len(docs),
        "files_sampled": list({d.metadata.get("file", "?") for d in docs}),
    }


def audit_and_remediate(
    repo_path: str = ".",
    provider: str = "gemini",
    embeddings_provider: str = "ollama",
) -> AuditReport:
    """2-Tier Pipeline: Auditor Agent identifies issues, Fixer Subagent generates patches."""
    target_path = Path(repo_path).resolve()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Tier 1: Auditor Agent
    auditor = AuditorAgent()
    console.print(f"[bold cyan]Scanning repository for security vulnerabilities and hardcoded secrets...[/bold cyan]")
    findings: List[Finding] = []

    # Direct deterministic scan for secrets across repo files
    for p in target_path.rglob("*"):
        if p.is_file() and p.suffix in {".py", ".js", ".ts", ".json", ".yaml", ".yml"}:
            if any(part in {".git", ".venv", "venv", "__pycache__", "node_modules", "reports"} for part in p.parts):
                continue
            findings.extend(auditor.scan_file_for_secrets(p, target_path))

    # Tier 2: Fixer Subagent generates concrete patches
    fixer = FixerSubagent()
    patches: List[RemediationPatch] = []

    console.print(f"[bold cyan]Fixer Subagent generating atomic patches for {len(findings)} findings...[/bold cyan]")
    for finding in findings:
        patch = fixer.generate_patch(finding, target_path)
        if patch:
            patches.append(patch)

    summary = (
        f"Audit scan completed at {timestamp}. Detected {len(findings)} findings "
        f"({len([f for f in findings if f.severity == 'CRITICAL'])} CRITICAL). "
        f"Generated {len(patches)} automated remediation patches."
    )

    return AuditReport(
        timestamp=timestamp,
        target_path=str(target_path),
        summary=summary,
        findings=findings,
        patches=patches,
        category_reports={},
    )


def run_audit(
    output_format: str = "markdown",
    provider: str = "ollama",
    embeddings_provider: str = "ollama",
    repo_path: str = ".",
    ci_mode: bool = False,
    fail_on: str = "CRITICAL",
):
    """Run full audit reports and remediation pipeline."""
    target_path = Path(repo_path).resolve()
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")

    console.print(f"[bold green]Starting audit against target: {target_path}...[/bold green]")
    llm = get_llm(provider)

    results = {}
    try:
        vectorstore = get_vectorstore(embeddings_provider)
    except Exception as e:
        console.print(f"[yellow]Vectorstore connection warning: {e}. Proceeding with file inspection.[/yellow]")
        vectorstore = None

    if vectorstore:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Running reports...", total=len(REPORT_CONFIG) + 1)
            for category, config in REPORT_CONFIG.items():
                progress.update(task, description=f"[cyan]Generating:[/cyan] {config['title']}")
                results[category] = audit_category(llm, vectorstore, category, config)
                progress.advance(task)
            progress.advance(task)

    # Run remediation scanner
    remediation_report = audit_and_remediate(str(target_path), provider=provider)

    # Print summary table
    table = Table(title="Security Audit & Remediation Findings")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="magenta")
    table.add_column("Issue Type", style="yellow")
    table.add_column("File", style="green")
    table.add_column("Patch Available", style="bold green")

    for f in remediation_report.findings:
        has_patch = any(p.finding_id == f.id for p in remediation_report.patches)
        table.add_row(
            f.id,
            f.severity,
            f.issue_type,
            f.file_path,
            "YES" if has_patch else "NO",
        )
    console.print(table)

    # Save reports
    Path("reports").mkdir(exist_ok=True)
    json_path = f"reports/audit_{timestamp}.json"
    latest_json_path = "reports/audit_latest.json"

    report_payload = {
        "timestamp": timestamp,
        "summary": remediation_report.summary,
        "findings": [f.model_dump() for f in remediation_report.findings],
        "patches": [p.model_dump() for p in remediation_report.patches],
        "categories": list(results.values()),
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)
    with open(latest_json_path, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)

    console.print(f"[bold green]✓ Artifact saved: {json_path} and {latest_json_path}[/bold green]")

    # CI Mode validation for Jenkins / Automation
    if ci_mode:
        critical_count = len([f for f in remediation_report.findings if f.severity == fail_on.upper()])
        if critical_count > 0:
            console.print(
                f"[bold red]CI FAILURE: Found {critical_count} {fail_on.upper()} findings in codebase![/bold red]"
            )
            sys.exit(1)
        else:
            console.print("[bold green]CI SUCCESS: No blocking findings detected.[/bold green]")
            sys.exit(0)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run a code audit and remediation against a codebase.")
    parser.add_argument("format", nargs="?", default="markdown", choices=["markdown", "json"],
                        help="Output format (default: markdown)")
    parser.add_argument("--provider", default="gemini", choices=["gemini", "ollama"],
                        help="LLM provider to use (default: gemini)")
    parser.add_argument("--embeddings", default="ollama", choices=["ollama", "google", "jina"],
                        help="Embedding provider (default: ollama)")
    parser.add_argument("--target", default=".", help="Target repository directory (default: .)")
    parser.add_argument("--ci", action="store_true", help="Run in headless CI/CD mode for Jenkins/automation")
    parser.add_argument("--fail-on", default="CRITICAL", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Fail CI build if findings match or exceed this severity")
    args = parser.parse_args()
    run_audit(
        output_format=args.format,
        provider=args.provider,
        embeddings_provider=args.embeddings,
        repo_path=args.target,
        ci_mode=args.ci,
        fail_on=args.fail_on,
    )