import os
import json
import hashlib
from pathlib import Path
from tqdm import tqdm

from dotenv import load_dotenv

from langchain_core.embeddings import Embeddings

try:
    from langchain_ollama import OllamaEmbeddings
except ImportError:
    OllamaEmbeddings = None

try:
    from langchain_qdrant import QdrantVectorStore
except ImportError:
    QdrantVectorStore = None

try:
    from langchain_text_splitters import Language, RecursiveCharacterTextSplitter
except ImportError:
    Language = None
    RecursiveCharacterTextSplitter = None

try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, VectorParams
except ImportError:
    QdrantClient = None
    Distance = None
    VectorParams = None

load_dotenv()

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "code_audit")
OLLAMA_EMBEDDING_MODEL = os.getenv("OLLAMA_EMBEDDING_MODEL", "unclemusclez/jina-embeddings-v2-base-code")
GOOGLE_EMBEDDING_MODEL = os.getenv("GOOGLE_EMBEDDING_MODEL", "gemini-embedding-001")
JINA_EMBEDDING_MODEL = os.getenv("JINA_EMBEDDING_MODEL", "jina-embeddings-v2-base-code")
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "1500"))
CHUNK_OVERLAP = int(os.getenv("CHUNK_OVERLAP", "150"))

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

def get_embeddings(provider: str):
    """Return the appropriate LangChain Embeddings object based on provider.
    
    All providers output 768-dimensional vectors to match the Qdrant collection.
    WARNING: You must use the same provider for both ingest and agent.py.
    Mixing providers will produce incorrect similarity search results.
    """
    if provider == "google":
        from langchain_google_genai import GoogleGenerativeAIEmbeddings
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not found in environment or .env")
        print(f"Embedding provider: Google ({GOOGLE_EMBEDDING_MODEL}, 768-dim)")
        # output_dimensionality=768 matches the Qdrant collection size
        return GoogleGenerativeAIEmbeddings(
            model=GOOGLE_EMBEDDING_MODEL,
            google_api_key=api_key,
            output_dimensionality=768,
            task_type="retrieval_document",
        )
    elif provider == "jina":
        api_key = os.getenv("JINA_API_KEY")
        if not api_key:
            raise ValueError("JINA_API_KEY not found in environment or .env. Get a free key at https://jina.ai")
        print(f"Embedding provider: Jina AI cloud ({JINA_EMBEDDING_MODEL}, 768-dim)")
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
        print(f"Embedding provider: Ollama local ({OLLAMA_EMBEDDING_MODEL})")
        return OllamaEmbeddings(model=OLLAMA_EMBEDDING_MODEL)


# Language mapping specifically for Python, Jupyter Notebooks, Java, C/C++
if Language is not None:
    LANG_MAP = {
        ".py": Language.PYTHON,
        ".ipynb": Language.PYTHON,
        ".java": Language.JAVA,
        ".cpp": Language.CPP,
        ".c": Language.CPP,
        ".cc": Language.CPP,
        ".cxx": Language.CPP,
        ".h": Language.CPP,
        ".hpp": Language.CPP,
    }
else:
    LANG_MAP = {
        ".py": "python",
        ".ipynb": "python",
        ".java": "java",
        ".cpp": "cpp",
        ".c": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".h": "cpp",
        ".hpp": "cpp",
    }

def get_splitter(ext: str):
    if RecursiveCharacterTextSplitter is None:
        raise ImportError("langchain-text-splitters is required for text splitting. Please install with 'pip install langchain-text-splitters'")
    lang = LANG_MAP.get(ext) if Language is not None else None
    if lang and Language is not None:
        return RecursiveCharacterTextSplitter.from_language(
            language=lang, chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP
        )
    return RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP
    )

def collect_files(repo_path: str) -> list[Path]:
    """Collect strictly Python (.py, .ipynb), Java (.java), and C/C++ (.cpp, .c, .h, .hpp) files,
    plus dependency manifests (requirements.txt, pom.xml, build.gradle) for SBOM tracking."""
    skip_dirs = {
        ".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build",
        ".next", ".nuxt", ".cache", "out", "public", ".docusaurus", "data", "env", ".env",
        "embeddings", "vectors", ".qdrant", "qdrant_storage", ".chroma", ".faiss",
        ".vscode", ".idea", ".pytest_cache", ".ruff_cache", ".mypy_cache",
        "vendor", "lib", "static", "assets", "themes", "bower_components", ".conda", "reports"
    }
    skip_files = {
        "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb",
        "embeddings.json", "vectors.json", "embeddings.csv", "vectors.csv", ".env"
    }
    
    # Strictly allow Python, Jupyter, Java, C/C++ code files
    code_extensions = {
        ".py", ".ipynb", ".java", ".cpp", ".c", ".cc", ".cxx", ".h", ".hpp"
    }
    # Manifest files needed to identify third-party packages for SBOM
    manifest_names = {
        "requirements.txt", "pom.xml", "build.gradle", "pyproject.toml"
    }

    files = []
    for p in Path(repo_path).rglob("*"):
        if not p.is_file():
            continue

        # Exclude video formats explicitly
        if p.suffix.lower() in {".mp4", ".mov", ".avi", ".mkv", ".webm"}:
            continue

        parts = p.parts
        # If the file path contains a "data" directory, bypass soft skip_dirs like "public" or "dist"
        if "data" in parts:
            forbidden_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv", "env", ".env"}
            if any(part in forbidden_dirs for part in parts):
                continue
        else:
            if any(part in skip_dirs for part in parts):
                continue

        if p.name.lower() in {name.lower() for name in skip_files} or p.suffix == ".lock" or ".min." in p.name:
            continue
        
        # Keep strictly requested code files + dependency manifests
        if p.suffix.lower() in code_extensions or p.name.lower() in manifest_names:
            files.append(p)

    return files

def ingest(repo_path: str, embeddings_provider: str = "ollama"):
    if QdrantClient is None or QdrantVectorStore is None:
        raise ImportError("qdrant-client and langchain-qdrant are required for ingestion.")

    client = QdrantClient(url=QDRANT_URL)

    # Create or recreate collection
    existing = [c.name for c in client.get_collections().collections]
    if COLLECTION_NAME in existing:
        print(f"Collection '{COLLECTION_NAME}' exists — deleting and re-indexing.")
        client.delete_collection(COLLECTION_NAME)

    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=768, distance=Distance.COSINE),
    )

    embeddings = get_embeddings(embeddings_provider)
    files = collect_files(repo_path)
    
    from collections import Counter
    ext_counts = Counter(f.suffix.lower() for f in files)
    print(f"\nFound {len(files)} total target files (.py, .ipynb, .cpp, .java, manifests). Breakdown:")
    for ext, count in ext_counts.most_common():
        print(f"  {ext or 'manifest'}: {count} files")
    print()

    all_docs = []
    file_chunk_counts = {}
    for fpath in tqdm(files, desc="Chunking"):
        try:
            raw_text = fpath.read_text(encoding="utf-8", errors="ignore")
            if not raw_text.strip():
                continue

            # Special parser for Jupyter Notebooks (.ipynb) to extract Python code & markdown cells cleanly
            if fpath.suffix.lower() == ".ipynb":
                try:
                    nb = json.loads(raw_text)
                    code_cells = []
                    for cell in nb.get("cells", []):
                        if cell.get("cell_type") == "code":
                            code_cells.extend(cell.get("source", []))
                            code_cells.append("\n\n")
                        elif cell.get("cell_type") == "markdown":
                            code_cells.append("# [Markdown Cell]\n")
                            code_cells.extend(cell.get("source", []))
                            code_cells.append("\n\n")
                    text = "".join(code_cells)
                    if not text.strip():
                        continue
                except Exception:
                    text = raw_text
            else:
                text = raw_text

            splitter = get_splitter(fpath.suffix.lower())
            raw_chunk_texts = splitter.split_text(text)
            rel_file_str = str(fpath.relative_to(repo_path))
            file_chunks = []

            from langchain_core.documents import Document
            search_offset = 0
            for c_text in raw_chunk_texts:
                if not c_text.strip():
                    continue
                c_idx = text.find(c_text, search_offset)
                if c_idx == -1:
                    c_idx = text.find(c_text)
                if c_idx != -1:
                    start_line = text[:c_idx].count("\n") + 1
                    end_line = start_line + c_text.count("\n")
                    search_offset = c_idx + len(c_text)
                else:
                    start_line = 1
                    end_line = 1 + c_text.count("\n")

                doc = Document(
                    page_content=c_text,
                    metadata={
                        "file": rel_file_str,
                        "ext": fpath.suffix,
                        "start_line": start_line,
                        "end_line": end_line,
                        "chunk_hash": hashlib.md5(c_text.encode()).hexdigest()[:8],
                    }
                )
                file_chunks.append(doc)

            all_docs.extend(file_chunks)
            if file_chunks:
                file_chunk_counts[rel_file_str] = len(file_chunks)
        except Exception as e:
            print(f"Skipped {fpath}: {e}")

    print(f"Total chunks generated: {len(all_docs)}")
    if file_chunk_counts:
        print("\nTop 5 files with the most chunks:")
        sorted_files = sorted(file_chunk_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for f, count in sorted_files:
            print(f"  - {f}: {count} chunks")
        print()

    print(f"Embedding {len(all_docs)} chunks into Qdrant in batches...")
    vector_store = QdrantVectorStore(
        client=client,
        collection_name=COLLECTION_NAME,
        embedding=embeddings,
    )

    batch_size = 256
    for i in range(0, len(all_docs), batch_size):
        batch = all_docs[i : i + batch_size]
        vector_store.add_documents(batch)
        print(f"✓ Indexed {min(i + batch_size, len(all_docs))} / {len(all_docs)} chunks...")

    print("✓ Ingestion complete.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Ingest a codebase into Qdrant for auditing.")
    parser.add_argument("path", nargs="?", default=".", help="Path to the repo (default: current dir)")
    parser.add_argument("--embeddings", default="ollama", choices=["ollama", "google", "jina"],
                        help="Embedding provider (default: ollama). Must match what agent.py uses!")
    args = parser.parse_args()
    ingest(args.path, args.embeddings)
