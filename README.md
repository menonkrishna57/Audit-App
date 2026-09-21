# Audit App

Audit App is a Python-based code auditing tool that ingests a repository into Qdrant and generates security-focused reports using LLM + RAG workflows.

## What it does

- Indexes source files into a Qdrant vector database (`ingest.py`)
- Runs audit reports from indexed chunks (`agent.py`)
- Provides a Streamlit dashboard for ingestion and interactive report generation (`app.py`)

## Report categories

The app supports four audit report types:

- **SBOM** — Software Bill of Materials
- **CBOM** — Cryptography Bill of Materials
- **RCA** — Root Cause Analysis for security issues
- **Gap Analysis** — OWASP Top 10 / CWE Top 25 coverage

Prompts and retrieval settings are defined in `prompts.py`.

## Tech stack

- Python
- LangChain
- Qdrant
- Ollama (local models)
- Google Gemini / Google Embeddings (optional)
- Jina Embeddings (optional)
- Streamlit

## Project files

- `ingest.py` — chunks and indexes repo files into Qdrant
- `agent.py` — retrieves chunks and generates audit reports
- `app.py` — Streamlit dashboard UI
- `prompts.py` — system prompts, report prompts, RAG queries
- `requirements.txt` — Python dependencies
- `run.md` — quick run notes

## Prerequisites

1. Python 3.10+ recommended
2. Qdrant running on `http://localhost:6333`
3. Optional providers:
   - `GOOGLE_API_KEY` for Gemini and Google embeddings
   - `JINA_API_KEY` for Jina embeddings
4. If using local mode, ensure Ollama is running with:
   - LLM model: `qwen3:4b-q4_K_M`
   - Embedding model: `unclemusclez/jina-embeddings-v2-base-code`

## Setup

```bash
pip install -r requirements.txt
```

Create `.env` (optional unless using cloud providers):

```env
GOOGLE_API_KEY=your_google_key
JINA_API_KEY=your_jina_key
```

## Start Qdrant

```bash
docker run -p 6333:6333 qdrant/qdrant
```

## Ingest a repository

Run ingestion first (or re-run when code changes):

```bash
# Default (local Ollama embeddings)
python ingest.py /path/to/repository

# Google embeddings
python ingest.py /path/to/repository --embeddings google

# Jina embeddings
python ingest.py /path/to/repository --embeddings jina
```

> Important: use the same embeddings provider in both `ingest.py` and `agent.py` / `app.py`.

## Run CLI audit

```bash
# Default: Ollama LLM + Ollama embeddings
python agent.py

# Gemini LLM + Google embeddings
python agent.py --provider gemini --embeddings google

# Gemini LLM + Jina embeddings
python agent.py --provider gemini --embeddings jina
```

JSON output:

```bash
python agent.py json --provider gemini --embeddings google
```

Reports are saved in `reports/`.

## Run Streamlit dashboard

```bash
streamlit run app.py
```

The dashboard includes:

- **Ingest Codebase** tab
- **Run Reports** tab
- provider selectors for embeddings and LLM
- option to save generated report markdown to disk

## Notes

- Qdrant must be online before ingestion and report generation.
- Ingestion recreates the `code_audit` collection each run.
- Only selected file types are indexed; large generated/vendor folders are skipped by design.
