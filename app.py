import os
import time
import requests
import streamlit as st
from datetime import datetime
from pathlib import Path
import json

from dotenv import load_dotenv
load_dotenv()

try:
    import tkinter as tk
    from tkinter import filedialog
    HAS_TKINTER = True
except Exception:
    HAS_TKINTER = False

from prompts import REPORT_CONFIG
from agent import get_llm, get_vectorstore, audit_category, run_audit, extract_text_content
from ingest import ingest

# --- Page Configuration ---
st.set_page_config(
    page_title="Audit-App | Security & Compliance Dashboard",
    layout="wide",
    page_icon="🛡️"
)

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
HAS_GOOGLE_KEY = bool(os.getenv("GOOGLE_API_KEY"))
HAS_JINA_KEY = bool(os.getenv("JINA_API_KEY"))

# --- Helper Functions ---
def check_qdrant_status():
    try:
        response = requests.get(QDRANT_URL, timeout=2)
        return response.status_code == 200
    except requests.RequestException:
        return False

def select_folder():
    """Opens a Windows Explorer dialog to select a folder if tkinter is available."""
    if not HAS_TKINTER:
        return ""
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        folder_path = filedialog.askdirectory(master=root)
        root.destroy()
        return folder_path
    except Exception:
        return ""

def list_past_reports():
    reports_dir = Path("reports")
    if not reports_dir.exists():
        return []
    return sorted(list(reports_dir.glob("*.md")), key=lambda p: p.stat().st_mtime, reverse=True)

# --- Sidebar Configuration ---
st.sidebar.image("https://img.shields.io/badge/Security-Audit_App-blue?style=for-the-badge&logo=shield", use_container_width=True)
st.sidebar.title("⚙️ System Settings")

# Qdrant Status
is_qdrant_online = check_qdrant_status()
if is_qdrant_online:
    st.sidebar.success("🟢 Qdrant Database: Online (port 6333)")
else:
    st.sidebar.error("🔴 Qdrant Database: Offline")
    st.sidebar.caption("Run `docker run -d -p 6333:6333 qdrant/qdrant` to start it.")

# API Key Status
if HAS_GOOGLE_KEY:
    st.sidebar.success("🔑 Google API Key: Configured")
else:
    st.sidebar.warning("⚠️ Google API Key: Missing from .env")

if HAS_JINA_KEY:
    st.sidebar.success("🔑 Jina API Key: Configured")
else:
    st.sidebar.info("ℹ️ Jina API Key: Not set (optional)")

st.sidebar.markdown("---")
st.sidebar.subheader("Model Configuration")

# Embedding Model Selector (smart default based on available keys)
default_emb_idx = 1 if HAS_GOOGLE_KEY else 0
embedding_provider = st.sidebar.selectbox(
    "Embedding Provider",
    options=["ollama", "google", "jina"],
    index=default_emb_idx,
    help="Must match the provider used during repository ingestion."
)

# Querying Model Selector
default_query_idx = 1 if HAS_GOOGLE_KEY else 0
query_provider = st.sidebar.selectbox(
    "Querying LLM Provider",
    options=["ollama", "gemini"],
    index=default_query_idx,
    help="LLM provider for generating reports."
)

gemini_model = None
if query_provider == "gemini":
    gemini_model = st.sidebar.selectbox(
        "Gemini Model",
        options=[
            "gemini-3.5-flash",
            "gemini-3.5-flash-lite",
            "gemini-3.8-flash",
            "gemini-3.5-pro",
        ],
        index=0,
        help="Select Gemini model version. (3.5-flash recommended; 3.5-flash-lite for fastest speed)."
    )

st.sidebar.markdown("---")
st.sidebar.info("💡 **Tip:** Always use the same Embedding Provider for both Ingestion and Reports.")

# --- Main Layout ---
st.title("🛡️ Code Audit & Security Compliance Dashboard")
st.caption("AI-driven code repository security auditing: SBOM, CBOM, Root Cause Analysis (RCA), and CWE/OWASP Gap Analysis with line numbers and recommended code fixes.")

tab1, tab2, tab3 = st.tabs(["📁 1. Ingest Codebase", "🔍 2. Run Security Audits", "📊 3. Past Audit Reports"])

# --- Tab 1: Ingest Codebase ---
with tab1:
    st.header("Index Codebase into Qdrant")
    st.markdown("Chunks source files and generates vector embeddings stored in Qdrant for semantic RAG auditing.")
    
    col1, col2 = st.columns([3, 1])
    
    if HAS_TKINTER and os.name == 'nt':
        with col2:
            st.write("")
            st.write("")
            if st.button("📂 Browse Folder"):
                folder_path = select_folder()
                if folder_path:
                    st.session_state["repo_path"] = folder_path
                    st.rerun()
                
    with col1:
        repo_path = st.text_input(
            "Codebase Path", 
            value=st.session_state.get("repo_path", "."),
            help="Path to the repository you want to audit (default: current directory)."
        )
        st.session_state["repo_path"] = repo_path

    if st.button("🚀 Start Repository Ingestion", type="primary", use_container_width=True):
        if not is_qdrant_online:
            st.error("Cannot ingest: Qdrant vector database is offline. Please start Qdrant container.")
        else:
            with st.status("Ingesting codebase into Qdrant...", expanded=True) as status:
                st.write(f"Target repository: `{Path(repo_path).resolve()}`")
                st.write(f"Embedding Provider: `{embedding_provider}`")
                try:
                    ingest(repo_path, embedding_provider)
                    status.update(label="✅ Ingestion completed successfully!", state="complete", expanded=False)
                    st.success("Codebase successfully vectorized and indexed into Qdrant collection!")
                except Exception as e:
                    status.update(label="❌ Ingestion failed", state="error", expanded=True)
                    st.error(f"Error during ingestion: {e}")

# --- Tab 2: Run Reports ---
with tab2:
    st.header("Execute Security Audits")
    
    if not is_qdrant_online:
        st.warning("⚠️ Qdrant is currently offline. Reports require vector database connectivity.")

    # High-level Quick Action
    st.subheader("⚡ Quick Action: Full Pipeline Audit")
    col_full, col_empty = st.columns([2, 3])
    with col_full:
        if st.button("🛡️ Run Complete Security Audit (SBOM + CBOM + RCA + CWE Gap Analysis)", type="primary", use_container_width=True):
            with st.spinner("Executing complete security audit pipeline (SBOM, CBOM, RCA, CWE Gap Analysis)..."):
                try:
                    run_audit(
                        output_format="markdown",
                        provider=query_provider,
                        embeddings_provider=embedding_provider,
                        categories=["sbom", "cbom", "rca", "gap_analysis"],
                        output_dir="reports",
                        model=gemini_model
                    )
                    st.success("✅ Complete security audit finished! All 4 audit reports and executive summary generated.")
                    st.info("Check **Tab 3: Past Audit Reports** to view and download the generated report with line numbers and recommended fixes.")
                except Exception as e:
                    st.error(f"Error during audit run: {e}")

    st.markdown("---")
    st.subheader("🔎 Individual Category Audit")
    
    categories = list(REPORT_CONFIG.keys())
    selected_report = st.selectbox(
        "Select Specific Audit Category",
        options=categories,
        format_func=lambda x: f"{REPORT_CONFIG[x]['title']} — {REPORT_CONFIG[x]['description']}"
    )
    
    if st.button(f"🔍 Run {REPORT_CONFIG[selected_report]['title']}"):
        with st.spinner(f"Generating {REPORT_CONFIG[selected_report]['title']}..."):
            try:
                llm = get_llm(query_provider, model_name=gemini_model)
                vectorstore = get_vectorstore(embedding_provider)
                
                config = REPORT_CONFIG[selected_report]
                result = audit_category(llm, vectorstore, selected_report, config)
                
                st.session_state["last_report_result"] = result
                st.session_state["last_report_title"] = config['title']
                st.session_state["last_report_key"] = selected_report
                
            except Exception as e:
                st.error(f"Error running category audit: {e}")

    # Display results if available
    if "last_report_result" in st.session_state:
        result = st.session_state["last_report_result"]
        title = st.session_state["last_report_title"]
        category_key = st.session_state.get("last_report_key", "audit")
        
        st.markdown("---")
        st.subheader(f"Results: {title}")
        
        st.info(f"**Chunks Analyzed:** {result['chunks_analyzed']} | **Files Sampled:** {len(result.get('files_sampled', []))}")
        
        findings_str = extract_text_content(result.get("findings", ""))
        
        # Download / Save actions
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
        report_md = f"# Internal Code Audit Report: {title}\n_Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}_\n\n"
        report_md += f"_Chunks analyzed: {result['chunks_analyzed']} | Files sampled: {len(result.get('files_sampled', []))}_\n\n"
        report_md += findings_str
        
        col_dl1, col_dl2 = st.columns([1, 1])
        with col_dl1:
            st.download_button(
                label="📥 Download Report (.md)",
                data=report_md,
                file_name=f"audit_{category_key}_{timestamp}.md",
                mime="text/markdown"
            )
        with col_dl2:
            st.download_button(
                label="📥 Download JSON (.json)",
                data=json.dumps(result, indent=2),
                file_name=f"audit_{category_key}_{timestamp}.json",
                mime="application/json"
            )
            
        with st.container(border=True):
            st.markdown(findings_str)

# --- Tab 3: Past Audit Reports ---
with tab3:
    st.header("Historical Audit Reports")
    st.markdown("Review and download previously generated code security audit reports stored in `reports/`.")
    
    past_reports = list_past_reports()
    if not past_reports:
        st.info("No past audit reports found in `reports/`. Run an audit in Tab 2 to generate your first report!")
    else:
        selected_file = st.selectbox(
            "Select Report to View",
            options=past_reports,
            format_func=lambda p: f"📄 {p.name} ({time.strftime('%Y-%m-%d %H:%M', time.localtime(p.stat().st_mtime))})"
        )
        
        if selected_file and selected_file.exists():
            report_text = selected_file.read_text(encoding="utf-8", errors="ignore")
            
            st.download_button(
                label=f"📥 Download {selected_file.name}",
                data=report_text,
                file_name=selected_file.name,
                mime="text/markdown"
            )
            
            st.markdown("---")
            with st.container(border=True):
                st.markdown(report_text)
