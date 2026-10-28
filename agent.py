import json
import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.markdown import Markdown
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn

from langchain_core.embeddings import Embeddings

try:
    from langchain_ollama import OllamaLLM, OllamaEmbeddings
except ImportError:
    OllamaLLM = None
    OllamaEmbeddings = None

try:
    from langchain_qdrant import QdrantVectorStore
    from qdrant_client import QdrantClient
except ImportError:
    QdrantVectorStore = None
    QdrantClient = None

from prompts import SYSTEM_PROMPT, REPORT_CONFIG

load_dotenv()  # loads GOOGLE_API_KEY from .env if present

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "code_audit")
OLLAMA_EMBEDDING_MODEL = os.getenv("OLLAMA_EMBEDDING_MODEL", "unclemusclez/jina-embeddings-v2-base-code")  # local fallback
GOOGLE_EMBEDDING_MODEL = os.getenv("GOOGLE_EMBEDDING_MODEL", "gemini-embedding-001")
JINA_EMBEDDING_MODEL = os.getenv("JINA_EMBEDDING_MODEL", "jina-embeddings-v2-base-code")

LLM_MODEL = os.getenv("OLLAMA_LLM_MODEL", "qwen3:4b-q4_K_M")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")

SUPPORTED_GEMINI_MODELS = [
    "gemini-3.5-flash-lite",
    "gemini-3.5-flash",
    "gemini-3.8-flash",
    "gemini-3.5-pro",
]

console = Console()

class DirectJinaEmbeddings(Embeddings):
    """Lightweight direct Jina AI embeddings client using requests (subclasses LangChain Embeddings)."""
    def __init__(self, jina_api_key: str, model_name: str = "jina-embeddings-v2-base-code"):
        self.api_key = jina_api_key
        self.model_name = model_name
        self.url = "https://api.jina.ai/v1/embeddings"

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        import requests
        if not texts:
            return []
        embeddings = []
        batch_size = 64
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            payload = {
                "model": self.model_name,
                "input": batch
            }
            resp = requests.post(self.url, json=payload, headers=headers, timeout=60)
            if resp.status_code != 200:
                raise ValueError(f"Jina API error ({resp.status_code}): {resp.text}")
            data = resp.json()["data"]
            data_sorted = sorted(data, key=lambda x: x.get("index", 0))
            for item in data_sorted:
                embeddings.append(item["embedding"])
        return embeddings

    def embed_query(self, text: str) -> list[float]:
        return self.embed_documents([text])[0]

def extract_text_content(res) -> str:
    """Extract clean string text from LLM response (handling string, list of dicts, or AIMessage)."""
    if res is None:
        return ""
    content = getattr(res, "content", res)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict) and "text" in part:
                parts.append(str(part["text"]))
            elif hasattr(part, "text"):
                parts.append(str(part.text))
            else:
                parts.append(str(part))
        return "\n".join(parts)
    return str(content)

def get_embeddings(provider: str):
    """Return the appropriate embeddings. Must match the provider used during ingest."""
    if provider == "google":
        from langchain_google_genai import GoogleGenerativeAIEmbeddings
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not found in environment or .env")
        return GoogleGenerativeAIEmbeddings(
            model=GOOGLE_EMBEDDING_MODEL,
            google_api_key=api_key,
            output_dimensionality=768,
            task_type="retrieval_query",  # query-side task type
        )
    elif provider == "jina":
        api_key = os.getenv("JINA_API_KEY")
        if not api_key:
            raise ValueError("JINA_API_KEY not found in environment or .env. Get a free key at https://jina.ai")
        try:
            from langchain_community.embeddings import JinaEmbeddings
            return JinaEmbeddings(
                jina_api_key=api_key,
                model_name=JINA_EMBEDDING_MODEL,
            )
        except ImportError:
            return DirectJinaEmbeddings(
                jina_api_key=api_key,
                model_name=JINA_EMBEDDING_MODEL,
            )
    else:
        if OllamaEmbeddings is None:
            raise ImportError("langchain-ollama is required for Ollama embeddings. Please install with 'pip install langchain-ollama'")
        return OllamaEmbeddings(model=OLLAMA_EMBEDDING_MODEL)


def get_llm(provider: str, model_name: str = None):
    """Return the appropriate LangChain LLM based on the chosen provider."""
    if provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            console.print("[bold red]Error:[/bold red] GOOGLE_API_KEY not found. Add it to your .env file or environment.")
            raise SystemExit(1)
        selected_model = model_name or os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
        console.print(f"[bold green]Provider:[/bold green] Google Gemini ({selected_model})\n")
        return ChatGoogleGenerativeAI(
            model=selected_model,
            temperature=0.1,
            google_api_key=api_key,
        )
    else:
        if OllamaLLM is None:
            raise ImportError("langchain-ollama is required for Ollama LLM. Please install with 'pip install langchain-ollama'")
        selected_model = model_name or LLM_MODEL
        console.print(f"[bold green]Provider:[/bold green] Ollama ({selected_model})\n")
        return OllamaLLM(
            model=selected_model,
            temperature=0.1,
            num_ctx=2048,  # Hard limit to save KV cache VRAM
        )


def get_vectorstore(embeddings_provider: str = "ollama"):
    if QdrantClient is None or QdrantVectorStore is None:
        raise ImportError("qdrant-client and langchain-qdrant are required for vector store.")
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

    # Run each RAG query and deduplicate results
    for query in config["queries"]:
        results = vectorstore.similarity_search(query, k=config["top_k"])
        for d in results:
            if d.page_content not in seen:
                seen.add(d.page_content)
                docs.append(d)

    if not docs:
        return {"category": category, "findings": "No relevant code found.", "chunks_analyzed": 0}

    # Build context from retrieved chunks with file and line range headers
    context_parts = []
    for i, doc in enumerate(docs):
        file_ref = doc.metadata.get("file", "unknown")
        start_line = doc.metadata.get("start_line")
        end_line = doc.metadata.get("end_line")
        line_info = f" (Lines {start_line}-{end_line})" if (start_line and end_line) else ""
        context_parts.append(f"--- Chunk {i+1} | File: {file_ref}{line_info} ---\n{doc.page_content}")
    context = "\n\n".join(context_parts)

    prompt = f"""{SYSTEM_PROMPT}

{config['prompt_template'].replace('{context}', context)}
"""

    response = llm.invoke(prompt)
    findings_text = extract_text_content(response)

    return {
        "category": category,
        "findings": findings_text,
        "chunks_analyzed": len(docs),
        "files_sampled": list({d.metadata.get("file", "?") for d in docs}),
    }

def run_audit(
    output_format: str = "markdown",
    provider: str = "ollama",
    embeddings_provider: str = "ollama",
    categories: list = None,
    output_dir: str = "reports",
    fail_on_critical: bool = False,
    model: str = None
):
    target_configs = {
        k: v for k, v in REPORT_CONFIG.items()
        if not categories or k in categories
    }

    if not target_configs:
        console.print("[bold red]Error: No valid categories selected.[/bold red]")
        return

    llm = get_llm(provider, model_name=model)
    vectorstore = get_vectorstore(embeddings_provider)

    console.print(f"[bold green]Starting audit ({', '.join(target_configs.keys())})...[/bold green]")
    
    results = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Running reports...", total=len(target_configs) + 1)
        
        for category, config in target_configs.items():
            progress.update(task, description=f"[cyan]Generating:[/cyan] {config['title']}")
            results[category] = audit_category(llm, vectorstore, category, config)
            progress.advance(task)

        progress.update(task, description="[cyan]Generating executive summary...[/cyan]")
        
        # Build summary
        summary_input = "\n\n".join(
            f"## {r['category'].upper()}\n{r['findings']}" for r in results.values()
        )
        summary_prompt = f"""You are a senior software engineer writing an executive summary of a code audit.
Below are findings across {len(target_configs)} audit categories. Write a concise 3-5 sentence executive summary
that highlights the most critical issues and the overall health of the codebase.

{summary_input}

Executive summary:"""

        summary_res = llm.invoke(summary_prompt)
        summary = extract_text_content(summary_res)

        progress.advance(task)
        progress.update(task, description="[green]Audit complete![/green]")

    # Assemble report
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    report_lines = [
        "# Internal Code Audit Report",
        f"_Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}_\n",
        "## Executive Summary",
        str(summary),
        "---",
    ]
    for r in results.values():
        report_lines += [
            f"\n## {r['category'].replace('_', ' ').title()}",
            f"_Chunks analyzed: {r['chunks_analyzed']} | Files sampled: {len(r.get('files_sampled', []))}_\n",
            str(r["findings"]),
        ]

    report_md = "\n".join(str(line) for line in report_lines)

    # Save
    out_dir_path = Path(output_dir)
    out_dir_path.mkdir(parents=True, exist_ok=True)
    out_path = out_dir_path / f"audit_{timestamp}.md"
    out_path.write_text(report_md, encoding="utf-8")

    console.print(f"\n[bold green]✓ Report saved to {out_path}[/bold green]")
    console.print(Markdown(report_md))

    if output_format == "json":
        json_path = out_dir_path / f"audit_{timestamp}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({"summary": summary, "categories": list(results.values())}, f, indent=2)
        console.print(f"[bold green]✓ JSON saved to {json_path}[/bold green]")

    # Write to GitHub Actions Step Summary if running in GitHub Actions CI
    github_summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if github_summary_path:
        try:
            with open(github_summary_path, "a", encoding="utf-8") as f:
                f.write(f"\n\n{report_md}\n")
            console.print("[bold green]✓ Appended audit report to GitHub Actions Step Summary[/bold green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not write to GITHUB_STEP_SUMMARY: {e}[/yellow]")

    if fail_on_critical:
        for r in results.values():
            findings_text = str(r.get("findings", "")).upper()
            if "CRITICAL" in findings_text:
                console.print("\n[bold red]CI Pipeline Check: CRITICAL severity findings detected in report![/bold red]")
                raise SystemExit(1)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run a code audit against an indexed codebase.")
    parser.add_argument("format", nargs="?", default="markdown", choices=["markdown", "json"],
                        help="Output format (default: markdown)")
    parser.add_argument("--provider", default="ollama", choices=["ollama", "gemini"],
                        help="LLM provider to use (default: ollama)")
    parser.add_argument("--model", default=None,
                        help="Specific model to use (e.g. gemini-3.5-flash-lite, gemini-3.5-flash, gemini-3.8-flash)")
    parser.add_argument("--embeddings", default="ollama", choices=["ollama", "google", "jina"],
                        help="Embedding provider — must match what was used during ingest (default: ollama)")
    parser.add_argument("--categories", nargs="+", choices=list(REPORT_CONFIG.keys()), default=list(REPORT_CONFIG.keys()),
                        help="Audit categories to run (e.g. sbom cbom) (default: all)")
    parser.add_argument("--output-dir", default="reports",
                        help="Output directory for reports (default: reports)")
    parser.add_argument("--fail-on-critical", action="store_true",
                        help="Fail with exit code 1 if CRITICAL findings are found (for CI/CD pipelines)")
    args = parser.parse_args()
    run_audit(
        output_format=args.format,
        provider=args.provider,
        embeddings_provider=args.embeddings,
        categories=args.categories,
        output_dir=args.output_dir,
        fail_on_critical=args.fail_on_critical,
        model=args.model
    )
