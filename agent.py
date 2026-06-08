import ast
import json
import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.markdown import Markdown
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from langchain_ollama import OllamaLLM, OllamaEmbeddings
from langchain_qdrant import QdrantVectorStore
from qdrant_client import QdrantClient

from prompts import AUDIT_CATEGORIES, DUPLICATE_INSTRUCTION

load_dotenv()  # loads GOOGLE_API_KEY from .env if present

QDRANT_URL = "http://localhost:6333"
COLLECTION_NAME = "code_audit"
OLLAMA_EMBEDDING_MODEL = "unclemusclez/jina-embeddings-v2-base-code"  # local fallback
OLLAMA_MODEL = "qwen3:4b"
GEMINI_MODEL = "gemini-2.0-flash-lite"  # free tier on AI Studio
TOP_K = 3   # chunks retrieved per category (larger chunks = fewer needed)

console = Console()

def get_embeddings(provider: str):
    """Return the appropriate embeddings. Must match the provider used during ingest."""
    if provider == "google":
        from langchain_google_genai import GoogleGenerativeAIEmbeddings
        api_key = os.getenv("GOOGLE_API_KEY")
        return GoogleGenerativeAIEmbeddings(
            model="models/text-embedding-004",
            google_api_key=api_key,
            task_type="retrieval_query",  # query-side task type
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
    """Return the appropriate LangChain LLM based on the chosen provider."""
    if provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            console.print("[bold red]Error:[/bold red] GOOGLE_API_KEY not found. Add it to your .env file.")
            raise SystemExit(1)
        console.print(f"[bold green]Provider:[/bold green] Google Gemini ({GEMINI_MODEL})\n")
        return ChatGoogleGenerativeAI(
            model=GEMINI_MODEL,
            temperature=0.1,
            google_api_key=api_key,
        )
    else:
        console.print(f"[bold green]Provider:[/bold green] Ollama ({OLLAMA_MODEL})\n")
        return OllamaLLM(model=OLLAMA_MODEL, temperature=0.1)


def get_vectorstore(embeddings_provider: str = "ollama"):
    client = QdrantClient(url=QDRANT_URL)
    embeddings = get_embeddings(embeddings_provider)
    return QdrantVectorStore(
        client=client,
        collection_name=COLLECTION_NAME,
        embedding=embeddings,
    )

def extract_function_signatures(repo_path: str) -> str:
    """Walk the repo and extract all function/method names using AST parsing.
    Returns a formatted string listing functions per file for duplicate detection."""
    skip_dirs = {
        ".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build",
        ".next", ".nuxt", ".cache", "vendor", "lib", "static", "assets",
        ".qdrant", "qdrant_storage", ".vscode", ".idea", ".pytest_cache"
    }
    lines = []
    for path in Path(repo_path).rglob("*.py"):
        if any(part in skip_dirs for part in path.parts):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source)
            funcs = [
                node.name for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            if funcs:
                rel = path.relative_to(repo_path)
                lines.append(f"File: {rel}\n  Functions: {', '.join(funcs)}")
        except SyntaxError:
            pass
    return "\n".join(lines) if lines else "No Python files found."

def audit_category(llm, vectorstore, category: str, config: dict) -> dict:
    # Retrieve relevant chunks
    docs = vectorstore.similarity_search(config["query"], k=TOP_K)

    if not docs:
        return {"category": category, "findings": "No relevant code found.", "chunks_analyzed": 0}

    # Build context from retrieved chunks
    context_parts = []
    for i, doc in enumerate(docs):
        file_ref = doc.metadata.get("file", "unknown")
        context_parts.append(f"--- Chunk {i+1} | File: {file_ref} ---\n{doc.page_content}")
    context = "\n\n".join(context_parts)

    prompt = f"""{config['instruction']}

== Code chunks to analyze ==
{context}

== Your findings ==
Be specific. Reference file names. If no issues found in this area, say so clearly.
"""

    response = llm.invoke(prompt)
    return {
        "category": category,
        "findings": response,
        "chunks_analyzed": len(docs),
        "files_sampled": list({d.metadata.get("file", "?") for d in docs}),
    }

def run_audit(output_format: str = "markdown", provider: str = "ollama", embeddings_provider: str = "ollama"):
    llm = get_llm(provider)
    vectorstore = get_vectorstore(embeddings_provider)

    console.print(f"[bold green]Starting audit...[/bold green]")
    
    results = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Starting audit...", total=len(AUDIT_CATEGORIES) + 1)
        
        for category, config in AUDIT_CATEGORIES.items():
            progress.update(task, description=f"[cyan]Auditing:[/cyan] {category}")
            results[category] = audit_category(llm, vectorstore, category, config)
            progress.advance(task)

        # Duplicate detection via static analysis (AST), not RAG
        progress.update(task, description="[cyan]Auditing:[/cyan] duplicate_logic (static)")
        signatures = extract_function_signatures(".")
        dup_prompt = f"""{DUPLICATE_INSTRUCTION}

== Function inventory ==
{signatures}

== Your findings =="""
        dup_response = llm.invoke(dup_prompt)
        results["duplicate_logic"] = {
            "category": "duplicate_logic",
            "findings": dup_response,
            "chunks_analyzed": signatures.count("File:"),
            "files_sampled": [],
        }
        progress.advance(task)

        progress.update(task, description="[cyan]Generating executive summary...[/cyan]")
        
        # Build summary
        summary_input = "\n\n".join(
            f"## {r['category'].upper()}\n{r['findings']}" for r in results.values()
        )
        summary_prompt = f"""You are a senior software engineer writing an executive summary of a code audit.
Below are findings across four audit categories. Write a concise 3-5 sentence executive summary
that highlights the most critical issues and the overall health of the codebase.

{summary_input}

Executive summary:"""

        summary = llm.invoke(summary_prompt)
        progress.update(task, description="[green]Audit complete![/green]")

    # Assemble report
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    report_lines = [
        f"# Internal Code Audit Report",
        f"_Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}_\n",
        "## Executive Summary",
        summary,
        "---",
    ]
    for r in results.values():
        report_lines += [
            f"\n## {r['category'].replace('_', ' ').title()}",
            f"_Chunks analyzed: {r['chunks_analyzed']} | Files sampled: {len(r.get('files_sampled', []))}_\n",
            r["findings"],
        ]

    report_md = "\n".join(report_lines)

    # Save
    Path("reports").mkdir(exist_ok=True)
    out_path = f"reports/audit_{timestamp}.md"
    Path(out_path).write_text(report_md, encoding="utf-8")

    console.print(f"\n[bold green]✓ Report saved to {out_path}[/bold green]")
    console.print(Markdown(report_md))

    if output_format == "json":
        json_path = f"reports/audit_{timestamp}.json"
        with open(json_path, "w") as f:
            json.dump({"summary": summary, "categories": list(results.values())}, f, indent=2)
        console.print(f"[bold green]✓ JSON saved to {json_path}[/bold green]")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run a code audit against an indexed codebase.")
    parser.add_argument("format", nargs="?", default="markdown", choices=["markdown", "json"],
                        help="Output format (default: markdown)")
    parser.add_argument("--provider", default="ollama", choices=["ollama", "gemini"],
                        help="LLM provider to use (default: ollama)")
    parser.add_argument("--embeddings", default="ollama", choices=["ollama", "google", "jina"],
                        help="Embedding provider — must match what was used during ingest (default: ollama)")
    args = parser.parse_args()
    run_audit(args.format, args.provider, args.embeddings)