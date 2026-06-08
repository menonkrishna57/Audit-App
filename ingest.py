import os
import hashlib
from pathlib import Path
from tqdm import tqdm

from dotenv import load_dotenv
from langchain_ollama import OllamaEmbeddings
from langchain_qdrant import QdrantVectorStore
from langchain_text_splitters import Language, RecursiveCharacterTextSplitter
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams

load_dotenv()

QDRANT_URL = "http://localhost:6333"
COLLECTION_NAME = "code_audit"
OLLAMA_EMBEDDING_MODEL = "unclemusclez/jina-embeddings-v2-base-code"
CHUNK_SIZE = 1500
CHUNK_OVERLAP = 150

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
            raise ValueError("GOOGLE_API_KEY not found in .env")
        print(f"Embedding provider: Google (text-embedding-004, 768-dim)")
        # output_dimensionality=768 matches the Qdrant collection size
        return GoogleGenerativeAIEmbeddings(
            model="models/text-embedding-004",
            google_api_key=api_key,
            task_type="retrieval_document",
        )
    elif provider == "jina":
        from langchain_community.embeddings import JinaEmbeddings
        api_key = os.getenv("JINA_API_KEY")
        if not api_key:
            raise ValueError("JINA_API_KEY not found in .env")
        print(f"Embedding provider: Jina AI cloud (jina-embeddings-v2-base-code)")
        return JinaEmbeddings(
            jina_api_key=api_key,
            model_name="jina-embeddings-v2-base-code",
        )
    else:
        print(f"Embedding provider: Ollama local ({OLLAMA_EMBEDDING_MODEL})")
        return OllamaEmbeddings(model=OLLAMA_EMBEDDING_MODEL)


# File extensions -> LangChain Language enum
LANG_MAP = {
    ".py": Language.PYTHON,
    ".js": Language.JS,
    ".ts": Language.JS,
    ".java": Language.JAVA,
    ".go": Language.GO,
    ".cpp": Language.CPP,
    ".c": Language.CPP,
    ".rb": Language.RUBY,
    ".rs": Language.RUST,
}

def get_splitter(ext: str):
    lang = LANG_MAP.get(ext)
    if lang:
        return RecursiveCharacterTextSplitter.from_language(
            language=lang, chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP
        )
    return RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP
    )

def collect_files(repo_path: str) -> list[Path]:
    skip_dirs = {
        ".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build",
        ".next", ".nuxt", ".cache", "out", "public", ".docusaurus", "data", "env", ".env",
        "embeddings", "vectors", ".qdrant", "qdrant_storage", ".chroma", ".faiss",
        ".vscode", ".idea", ".pytest_cache", ".ruff_cache", ".mypy_cache",
        # Third-party / vendor code — excluded to prevent polluting audit results
        "vendor", "lib", "static", "assets", "themes", "bower_components"
    }
    skip_files = {
        "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb",
        "embeddings.json", "vectors.json", "embeddings.csv", "vectors.csv", ".env"
    }
    extensions = set(LANG_MAP.keys()) | {
        ".md", ".yaml", ".yml", ".toml", ".json", ".jsonl", ".csv", ".tsv", ".xml"
    }
    files = []
    for p in Path(repo_path).rglob("*"):
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
        if p.is_file() and p.suffix in extensions:
            files.append(p)
    return files

def ingest(repo_path: str, embeddings_provider: str = "ollama"):
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
    ext_counts = Counter(f.suffix for f in files)
    print(f"\nFound {len(files)} total files. Breakdown:")
    for ext, count in ext_counts.most_common():
        print(f"  {ext or 'no-extension'}: {count} files")
    print()

    all_docs = []
    file_chunk_counts = {}
    for fpath in tqdm(files, desc="Chunking"):
        try:
            text = fpath.read_text(encoding="utf-8", errors="ignore")
            if not text.strip():
                continue
            splitter = get_splitter(fpath.suffix)
            chunks = splitter.create_documents(
                texts=[text],
                metadatas=[{
                    "file": str(fpath.relative_to(repo_path)),
                    "ext": fpath.suffix,
                    "chunk_hash": hashlib.md5(text.encode()).hexdigest()[:8],
                }]
            )
            all_docs.extend(chunks)
            if chunks:
                file_chunk_counts[str(fpath.relative_to(repo_path))] = len(chunks)
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