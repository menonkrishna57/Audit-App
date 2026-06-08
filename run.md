# Running the Code Audit Tool

## Prerequisites
- Ensure Qdrant is running locally (e.g., `docker run -p 6333:6333 qdrant/qdrant`).
- If using Google Gemini or Jina AI for embeddings/LLM, ensure your `.env` file contains `GOOGLE_API_KEY` or `JINA_API_KEY`.

## 1. Index your repo (run once, or re-run when code changes)
The indexing step chunks your codebase and stores it in Qdrant. You must specify an embeddings provider (`ollama` by default).

```powershell
# Default: Uses local Ollama for embeddings
python ingest.py /path/to/your/repo

# Cloud: Uses Google or Jina for embeddings (Requires API Keys)
python ingest.py /path/to/your/repo --embeddings google
python ingest.py /path/to/your/repo --embeddings jina
```

**⚠️ Critical Rule:** The `--embeddings` provider you choose here MUST be the exact same one you use for `agent.py`.

## 2. Run the audit
The agent runs a high-performance asynchronous pipeline to generate SBOM, CBOM, RCA, and Gap Analysis reports. 

```powershell
# Default: Uses Ollama for LLM and Ollama for embeddings
python agent.py

# Fully Free Cloud: Gemini for LLM + Google for embeddings
python agent.py --provider gemini --embeddings google

# Mix: Gemini for LLM + Jina for embeddings
python agent.py --provider gemini --embeddings jina
```

## 3. Output Formats
By default, the report is saved as a Markdown file in the `reports/` directory. You can optionally export it in a structured JSON format.

```powershell
# Outputs BOTH Markdown and JSON formats
python agent.py json --provider gemini --embeddings google
```