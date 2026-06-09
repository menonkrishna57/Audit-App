import os
import time
import requests
import streamlit as st
import tkinter as tk
from tkinter import filedialog
from datetime import datetime
from pathlib import Path
import json

from prompts import REPORT_CONFIG
from agent import get_llm, get_vectorstore, audit_category
from ingest import ingest

# --- Page Configuration ---
st.set_page_config(page_title="Audit App Dashboard", layout="wide", page_icon="🛡️")

# --- Helper Functions ---
def check_qdrant_status():
    try:
        response = requests.get("http://localhost:6333", timeout=2)
        return response.status_code == 200
    except requests.RequestException:
        return False

def select_folder():
    """Opens a Windows Explorer dialog to select a folder."""
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    folder_path = filedialog.askdirectory(master=root)
    root.destroy()
    return folder_path

# --- Sidebar Configuration ---
st.sidebar.title("⚙️ Settings")

# Qdrant Status
is_qdrant_online = check_qdrant_status()
if is_qdrant_online:
    st.sidebar.success("🟢 Qdrant Database: Online")
else:
    st.sidebar.error("🔴 Qdrant Database: Offline")

# Embedding Model Selector
st.sidebar.subheader("Models")
embedding_provider = st.sidebar.selectbox(
    "Embedding Model",
    options=["ollama", "google", "jina"],
    index=0,
    help="Must match the provider used during ingestion."
)

# Querying Model Selector
query_provider = st.sidebar.selectbox(
    "Querying Model",
    options=["ollama", "gemini"],
    index=0,
    help="LLM provider for generating reports."
)

st.sidebar.markdown("---")
st.sidebar.info("Make sure to restart ingestion if you change the Embedding Model!")

# --- Main Layout ---
st.title("🛡️ Code Audit Dashboard")

tab1, tab2 = st.tabs(["📁 Ingest Codebase", "📄 Run Reports"])

# --- Tab 1: Ingest Codebase ---
with tab1:
    st.header("Ingest Codebase into Qdrant")
    
    st.markdown("Select a folder using the Windows Explorer dialog, or paste the path manually below.")
    
    col1, col2 = st.columns([3, 1])
    
    with col2:
        st.write("") # Spacing
        st.write("")
        if st.button("📂 Browse Folder (Windows)"):
            folder_path = select_folder()
            if folder_path:
                st.session_state["repo_path"] = folder_path
                st.rerun()
                
    with col1:
        repo_path = st.text_input(
            "Codebase Path", 
            value=st.session_state.get("repo_path", "."),
            help="Path to the repository you want to audit."
        )
        # Update session state if user types manually
        st.session_state["repo_path"] = repo_path

    if st.button("🚀 Start Ingestion", type="primary"):
        if not is_qdrant_online:
            st.error("Cannot ingest: Qdrant is offline. Please start your Qdrant container.")
        else:
            with st.status("Ingesting codebase... This might take a while.", expanded=True) as status:
                st.write(f"Target path: `{repo_path}`")
                st.write(f"Embedding Provider: `{embedding_provider}`")
                st.write("Check your terminal for detailed progress output.")
                try:
                    ingest(repo_path, embedding_provider)
                    status.update(label="✅ Ingestion complete!", state="complete", expanded=False)
                    st.success("Codebase successfully ingested and indexed!")
                except Exception as e:
                    status.update(label="❌ Ingestion failed", state="error", expanded=True)
                    st.error(f"Error during ingestion: {e}")

# --- Tab 2: Run Reports ---
with tab2:
    st.header("Run Audit Reports")
    
    if not is_qdrant_online:
        st.warning("⚠️ Qdrant is offline. Reports might fail if they require vector search.")

    st.markdown("Select a report category below to run an audit using the ingested codebase.")
    
    # Create a grid of buttons for reports
    categories = list(REPORT_CONFIG.keys())
    
    selected_report = st.selectbox("Select Report to Run", options=categories, format_func=lambda x: REPORT_CONFIG[x]['title'])
    
    if st.button(f"🔍 Run {REPORT_CONFIG[selected_report]['title']}", type="primary"):
        with st.spinner(f"Running {selected_report} report..."):
            try:
                # Initialize models
                llm = get_llm(query_provider)
                vectorstore = get_vectorstore(embedding_provider)
                
                # Run the audit
                config = REPORT_CONFIG[selected_report]
                result = audit_category(llm, vectorstore, selected_report, config)
                
                # Store result in session state to persist across reruns
                st.session_state["last_report_result"] = result
                st.session_state["last_report_title"] = config['title']
                
            except Exception as e:
                st.error(f"Error running report: {e}")

    # Display results if available
    if "last_report_result" in st.session_state:
        result = st.session_state["last_report_result"]
        title = st.session_state["last_report_title"]
        
        st.markdown("---")
        st.subheader(f"Results: {title}")
        
        st.info(f"**Chunks Analyzed:** {result['chunks_analyzed']} | **Files Sampled:** {len(result.get('files_sampled', []))}")
        
        # Add a save button
        col_save, _ = st.columns([1, 4])
        with col_save:
            if st.button("💾 Save Report to Disk"):
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
                report_md = f"# Internal Code Audit Report: {title}\n_Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}_\n\n"
                report_md += f"_Chunks analyzed: {result['chunks_analyzed']} | Files sampled: {len(result.get('files_sampled', []))}_\n\n"
                report_md += result['findings']
                
                Path("reports").mkdir(exist_ok=True)
                out_path = f"reports/audit_{selected_report}_{timestamp}.md"
                Path(out_path).write_text(report_md, encoding="utf-8")
                st.success(f"Report saved to `{out_path}`")
                
        with st.container(border=True):
            st.markdown(result["findings"])
