import ast
import json
import os
import asyncio
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.markdown import Markdown
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from langchain_ollama import OllamaLLM, OllamaEmbeddings
from langchain_qdrant import QdrantVectorStore
from qdrant_client import QdrantClient

from prompts import SYSTEM_PROMPT, REPORT_CONFIG

load_dotenv()  # loads GOOGLE_API_KEY from .env if present

QDRANT_URL = "http://localhost:6333"
COLLECTION_NAME = "code_audit"
OLLAMA_EMBEDDING_MODEL = "unclemusclez/jina-embeddings-v2-base-code"  # local fallback

LLM_MODEL = "qwen3:4b-q4_K_M"
GEMINI_MODEL = "gemini-2.0-flash-lite"  # free tier on AI Studio

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
        console.print(f"[bold green]Provider:[/bold green] Ollama ({LLM_MODEL})\n")
        return OllamaLLM(
            model=LLM_MODEL, 
            temperature=0.1,
            num_ctx=2048,  # Hard limit to save KV cache VRAM
        )


def get_vectorstore(embeddings_provider: str = "ollama"):
    client = QdrantClient(url=QDRANT_URL)
    embeddings = get_embeddings(embeddings_provider)
    return QdrantVectorStore(
        client=client,
        collection_name=COLLECTION_NAME,
        embedding=embeddings,
    )

async def audit_category(llm, vectorstore, category: str, config: dict, progress: Progress, task_id) -> dict:
    docs = []
    seen = set()
    # Execute searches concurrently for all queries in the config
    
    def sync_search(query):
        return vectorstore.similarity_search(query, k=config["top_k"])
        
    search_tasks = [asyncio.to_thread(sync_search, q) for q in config["queries"]]
    results = await asyncio.gather(*search_tasks)
    
    for res_list in results:
        for d in res_list:
            if d.page_content not in seen:
                seen.add(d.page_content)
                docs.append(d)

    if not docs:
        progress.advance(task_id)
        return {"category": category, "findings": "No relevant code found.", "chunks_analyzed": 0}

    # Build context from retrieved chunks
    context_parts = []
    for i, doc in enumerate(docs):
        file_ref = doc.metadata.get("file", "unknown")
        context_parts.append(f"--- Chunk {i+1} | File: {file_ref} ---\n{doc.page_content}")
    context = "\n\n".join(context_parts)

    prompt = f"""{SYSTEM_PROMPT}

{config['prompt_template'].replace('{context}', context)}
"""

    response = await llm.ainvoke(prompt)
    progress.advance(task_id)
    
    return {
        "category": category,
        "findings": response,
        "chunks_analyzed": len(docs),
        "files_sampled": list({d.metadata.get("file", "?") for d in docs}),
    }

async def run_audit_async(output_format: str = "markdown", provider: str = "ollama", embeddings_provider: str = "ollama"):
    llm = get_llm(provider)
    vectorstore = get_vectorstore(embeddings_provider)

    console.print(f"[bold green]Starting async audit...[/bold green]")
    
    results = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        main_task = progress.add_task("[cyan]Running reports concurrently...", total=len(REPORT_CONFIG) + 1)
        
        # Dispatch all categories concurrently
        tasks = []
        for category, config in REPORT_CONFIG.items():
            tasks.append(audit_category(llm, vectorstore, category, config, progress, main_task))
            
        completed_reports = await asyncio.gather(*tasks)
        for rep in completed_reports:
            results[rep["category"]] = rep

        progress.update(main_task, description="[cyan]Generating executive summary...[/cyan]")
        
        # Build summary
        summary_input = "\n\n".join(
            f"## {r['category'].upper()}\n{r['findings']}" for r in results.values()
        )
        summary_prompt = f"""You are a senior software engineer writing an executive summary of a code audit.
Below are findings across {len(REPORT_CONFIG)} audit categories. Write a concise 3-5 sentence executive summary
that highlights the most critical issues and the overall health of the codebase.

{summary_input}

Executive summary:"""

        summary = await llm.ainvoke(summary_prompt)
        progress.advance(main_task)
        progress.update(main_task, description="[green]Audit complete![/green]")

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
    asyncio.run(run_audit_async(args.format, args.provider, args.embeddings))