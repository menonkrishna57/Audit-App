import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown
from langchain_ollama import OllamaLLM, OllamaEmbeddings
from langchain_qdrant import QdrantVectorStore
from qdrant_client import QdrantClient

from prompts import AUDIT_CATEGORIES

QDRANT_URL = "http://localhost:6333"
COLLECTION_NAME = "code_audit"
EMBEDDING_MODEL = "unclemusclez/jina-embeddings-v2-base-code"
LLM_MODEL = "qwen3:4b"
TOP_K = 8   # chunks retrieved per category

console = Console()

def get_vectorstore():
    client = QdrantClient(url=QDRANT_URL)
    embeddings = OllamaEmbeddings(model=EMBEDDING_MODEL)
    return QdrantVectorStore(
        client=client,
        collection_name=COLLECTION_NAME,
        embedding=embeddings,
    )

def audit_category(llm, vectorstore, category: str, config: dict) -> dict:
    console.print(f"\n[bold cyan]Auditing:[/bold cyan] {category}")

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

def run_audit(output_format: str = "markdown"):
    llm = OllamaLLM(model=LLM_MODEL, temperature=0.1)
    vectorstore = get_vectorstore()

    console.print(f"[bold green]Starting audit with {LLM_MODEL}[/bold green]")
    
    results = {}
    for category, config in AUDIT_CATEGORIES.items():
        results[category] = audit_category(llm, vectorstore, category, config)

    # Build summary
    summary_input = "\n\n".join(
        f"## {r['category'].upper()}\n{r['findings']}" for r in results.values()
    )
    summary_prompt = f"""You are a senior software engineer writing an executive summary of a code audit.
Below are findings across four audit categories. Write a concise 3-5 sentence executive summary
that highlights the most critical issues and the overall health of the codebase.

{summary_input}

Executive summary:"""

    console.print("\n[bold cyan]Generating executive summary...[/bold cyan]")
    summary = llm.invoke(summary_prompt)

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
    import sys
    fmt = sys.argv[1] if len(sys.argv) > 1 else "markdown"
    run_audit(fmt)