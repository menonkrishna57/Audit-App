# Audit App

Audit App is a Python-based code auditing tool that ingests a repository into Qdrant and generates security-focused reports using LLM + RAG workflows.

## What it does

- Indexes source files into a Qdrant vector database (`ingest.py`)
- Runs audit reports from indexed chunks (`agent.py`)
- Provides a Streamlit dashboard for ingestion and interactive report generation (`app.py`)
- Automated CI/CD security pipeline verifying SBOM & CBOM and packaging container images (`.github/workflows/ci-cd.yml`)

## Report categories

The app supports four audit report types:

- **SBOM** — Software Bill of Materials (inventories packages, versions, and dependencies)
- **CBOM** — Cryptography Bill of Materials (crypto primitives, quantum-safety, and algorithm weaknesses)
- **RCA** — Root Cause Analysis for security issues
- **Gap Analysis** — OWASP Top 10 / CWE Top 25 coverage

Prompts and retrieval settings are defined in `prompts.py`.

## Tech stack

- Python 3.10+
- LangChain
- Qdrant Vector Database
- Ollama (local models)
- Google Gemini / Google Embeddings (optional)
- Jina Embeddings (optional)
- Streamlit
- Docker & GitHub Actions CI/CD

## Project files

- `ingest.py` — Chunks and indexes repo files into Qdrant
- `agent.py` — Retrieves chunks and generates audit reports (CLI)
- `app.py` — Streamlit dashboard UI
- `prompts.py` — System prompts, report prompts, RAG queries
- `ci_security_audit.py` — CI pipeline runner executing SBOM and CBOM security measures
- `Dockerfile` & `docker-compose.yml` — Containerization and service orchestration
- `.github/workflows/ci-cd.yml` — Automated CI/CD workflow (SBOM, CBOM, tests, GHCR delivery)
- `tests/test_audit.py` — Test suite for ingestion, parsing, and audit integrity
- `requirements.txt` — Python dependencies
- `run.md` — Quick run notes

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
QDRANT_URL=http://localhost:6333
```

## Running with Docker Compose

Run the entire stack (Qdrant + Audit-App Streamlit UI) with one command:

```bash
docker compose up -d
```

Access the dashboard at `http://localhost:8501`.

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

> **Important:** Use the same embeddings provider in both `ingest.py` and `agent.py` / `app.py`.

## Run CLI audit

```bash
# Default: Ollama LLM + Ollama embeddings
python agent.py

# Gemini LLM + Google embeddings
python agent.py --provider gemini --embeddings google

# Run specific categories (e.g. SBOM and CBOM only)
python agent.py --categories sbom cbom --provider gemini --embeddings google
```

JSON output:

```bash
python agent.py json --provider gemini --embeddings google
```

Reports are saved in `reports/`.

## CI/CD Pipeline (GitHub Actions)

The repository includes an enterprise-grade CI/CD pipeline in [`.github/workflows/ci-cd.yml`](.github/workflows/ci-cd.yml):

### 1. Continuous Integration (CI)
- **Automated Testing:** Runs `pytest` test suite to verify prompt structure, file collection, and SBOM/CBOM extraction.
- **In-Pipeline Security Audit:**
  - Spins up a Qdrant container service.
  - Executes `ci_security_audit.py` to produce **SBOM** and **CBOM** security reports.
  - Automatically posts the full SBOM and CBOM tables directly to GitHub Actions **Step Summary**.
  - Uploads the audit reports as downloadable workflow artifacts (`audit-reports`).

### 2. Continuous Delivery (CD)
- On push to `main` or version tags (`v*`), automatically builds a multi-platform Docker container.
- Publishes the container image to **GitHub Container Registry (GHCR)**:
  `ghcr.io/<owner>/<repo>:latest`

### GitHub Secrets Configuration
Configure the following under **Settings > Secrets and variables > Actions**:
- `GOOGLE_API_KEY` *(Optional)*: Enables full Gemini + Google RAG embeddings in CI. (If omitted, deterministic SBOM/CBOM extraction runs without breaking the build).
- `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` *(Optional)*: If you also want images pushed to Docker Hub in addition to GHCR.

## Run Streamlit dashboard locally

```bash
streamlit run app.py
```

The dashboard includes:
- **Ingest Codebase** tab
- **Run Reports** tab
- Provider selectors for embeddings and LLM
- Option to save generated report markdown to disk

## Notes

- Qdrant must be online before ingestion and report generation.
- Ingestion recreates the `code_audit` collection each run.
- Only selected file types are indexed; large generated/vendor folders are skipped by design.
