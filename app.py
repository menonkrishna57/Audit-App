import os
import sys
import time
import requests
import streamlit as st
import tkinter as tk
from tkinter import filedialog
from datetime import datetime
from pathlib import Path
import json

from prompts import REPORT_CONFIG
from agent import get_llm, get_vectorstore, audit_category, audit_and_remediate, GEMINI_MODEL
from ingest import ingest
from remediation import GitManager, Finding, RemediationPatch, RemediationResult, AuditReport

# --- Page Configuration & Design System ---
st.set_page_config(
    page_title="Security Audit & Remediation Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom High-Agency Styling (design-taste-frontend: No emojis, desaturated neutrals, calibrated accents)
st.markdown("""
<style>
    /* Global Typography & Palette */
    @import url('https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Geist', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    code, pre, .stCodeBlock {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Severity Badges */
    .badge-critical {
        background-color: rgba(239, 68, 68, 0.15);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.3);
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.75rem;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        display: inline-block;
    }

    .badge-high {
        background-color: rgba(249, 115, 22, 0.15);
        color: #fb923c;
        border: 1px solid rgba(249, 115, 22, 0.3);
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.75rem;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        display: inline-block;
    }

    .badge-success {
        background-color: rgba(16, 185, 129, 0.15);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.3);
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.75rem;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        display: inline-block;
    }

    /* Diff Styling */
    .diff-del {
        background-color: rgba(239, 68, 68, 0.2);
        color: #fca5a5;
        padding: 2px 4px;
        border-left: 3px solid #ef4444;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        margin: 2px 0;
    }

    .diff-add {
        background-color: rgba(16, 185, 129, 0.2);
        color: #6ee7b7;
        padding: 2px 4px;
        border-left: 3px solid #10b981;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        margin: 2px 0;
    }

    .diff-container {
        background-color: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 6px;
        padding: 12px;
        margin: 8px 0;
    }
</style>
""", unsafe_allow_html=True)


# --- Helper Functions ---
def check_qdrant_status():
    try:
        response = requests.get("http://localhost:6333", timeout=2)
        return response.status_code == 200
    except requests.RequestException:
        return False


def select_folder():
    """Opens a system directory dialog to select a folder."""
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    folder_path = filedialog.askdirectory(master=root)
    root.destroy()
    return folder_path


# --- Sidebar Configuration ---
st.sidebar.markdown("### SYSTEM SETTINGS")

# Qdrant Status Indicator
is_qdrant_online = check_qdrant_status()
if is_qdrant_online:
    st.sidebar.markdown('<span class="badge-success">Qdrant Vector Engine: Online</span>', unsafe_allow_html=True)
else:
    st.sidebar.markdown('<span class="badge-critical">Qdrant Vector Engine: Offline</span>', unsafe_allow_html=True)

st.sidebar.markdown("---")
st.sidebar.markdown("### MODEL CONFIGURATION")

# Embedding Model Selector
embedding_provider = st.sidebar.selectbox(
    "Embedding Provider",
    options=["ollama", "google", "jina"],
    index=0,
    help="Must match the provider used during ingestion."
)

# Querying Model Selector
query_provider = st.sidebar.selectbox(
    "Auditor LLM Engine",
    options=["gemini", "ollama"],
    index=0,
    help=f"Select 'gemini' for {GEMINI_MODEL} via google-genai SDK, or 'ollama' for local inference."
)

st.sidebar.caption(f"Active Gemini Model: **{GEMINI_MODEL}** (google-genai)")
st.sidebar.markdown("---")
st.sidebar.caption("CI/CD Automation: Use `python agent.py --ci` for headless Jenkins verification.")


# --- Main Dashboard Layout ---
st.markdown("## Codebase Audit & Automated Remediation")
st.caption("AI-powered static security analysis, secret extraction, and Git-isolated remediation.")

tab1, tab2, tab3 = st.tabs([
    "1. Ingestion & Indexing",
    "2. Audit Reports",
    "3. Remediation & Fixes (1-Click Apply)",
])


# ─────────────────────────────────────────────────────────────────────────────
# TAB 1: INGESTION & INDEXING
# ─────────────────────────────────────────────────────────────────────────────
with tab1:
    st.markdown("### Ingest Repository into Vector Database")
    st.caption("Extracts AST-aware code chunks and embeds them for semantic similarity search.")

    col1, col2 = st.columns([3, 1])

    with col2:
        st.write("")
        st.write("")
        if st.button("Browse Folder..."):
            folder_path = select_folder()
            if folder_path:
                st.session_state["repo_path"] = folder_path
                st.rerun()

    with col1:
        repo_path = st.text_input(
            "Repository Root Path",
            value=st.session_state.get("repo_path", "."),
            help="Path to the repository you want to audit."
        )
        st.session_state["repo_path"] = repo_path

    if st.button("Start Ingestion & Indexing", type="primary"):
        if not is_qdrant_online:
            st.error("Cannot ingest: Qdrant database is offline. Please launch Qdrant container.")
        else:
            with st.status("Ingesting codebase... This might take a few moments.", expanded=True) as status:
                st.write(f"Target repository: `{repo_path}`")
                st.write(f"Embedding Provider: `{embedding_provider}`")
                try:
                    ingest(repo_path, embedding_provider)
                    status.update(label="Ingestion and vector indexing complete", state="complete", expanded=False)
                    st.success("Repository successfully indexed into Qdrant collection.")
                except Exception as e:
                    status.update(label="Ingestion failed", state="error", expanded=True)
                    st.error(f"Error during ingestion: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# TAB 2: AUDIT REPORTS
# ─────────────────────────────────────────────────────────────────────────────
with tab2:
    st.markdown("### Security & Compliance Audit Reports")
    st.caption("Generate structured findings across SBOM, Cryptography, Root Cause Analysis, and OWASP Gaps.")

    if not is_qdrant_online:
        st.warning("Vector engine is offline. Reports requiring similarity search might fall back to disk scanning.")

    categories = list(REPORT_CONFIG.keys())
    selected_report = st.selectbox(
        "Select Audit Category",
        options=categories,
        format_func=lambda x: REPORT_CONFIG[x]['title'],
    )

    if st.button(f"Run {REPORT_CONFIG[selected_report]['title']}", type="primary"):
        with st.spinner(f"Auditor Agent analyzing codebase ({query_provider} - {GEMINI_MODEL if query_provider == 'gemini' else 'local'})..."):
            try:
                llm = get_llm(query_provider)
                vectorstore = get_vectorstore(embedding_provider)
                config = REPORT_CONFIG[selected_report]

                result = audit_category(llm, vectorstore, selected_report, config)
                st.session_state["last_report_result"] = result
                st.session_state["last_report_title"] = config['title']
                st.session_state["last_report_key"] = selected_report
            except Exception as e:
                st.error(f"Error executing audit report: {e}")

    if "last_report_result" in st.session_state:
        result = st.session_state["last_report_result"]
        title = st.session_state["last_report_title"]

        st.markdown("---")
        st.markdown(f"#### Audit Output: {title}")
        st.caption(f"Chunks analyzed: {result['chunks_analyzed']} | Sampled files: {len(result.get('files_sampled', []))}")

        col_save, col_remed = st.columns([1, 1])
        with col_save:
            if st.button("Export Markdown Report"):
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
                report_md = f"# Code Audit Report: {title}\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
                report_md += result['findings']
                Path("reports").mkdir(exist_ok=True)
                out_path = f"reports/audit_{st.session_state.get('last_report_key', 'report')}_{timestamp}.md"
                Path(out_path).write_text(report_md, encoding="utf-8")
                st.success(f"Saved to `{out_path}`")

        with col_remed:
            if st.button("Scan for Fixes in Tab 3 ->"):
                st.session_state["run_remediation_trigger"] = True
                st.rerun()

        with st.container(border=True):
            st.markdown(result["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# TAB 3: REMEDIATION & FIXES (1-CLICK APPLY WITH GIT ISOLATION)
# ─────────────────────────────────────────────────────────────────────────────
with tab3:
    st.markdown("### Automated Code Remediation & Git Isolation")
    st.caption("Fix hardcoded secrets, extract credentials into .env, ensure dependencies, and apply fixes safely to a dedicated Git branch.")

    target_repo = st.session_state.get("repo_path", ".")
    git_manager = GitManager(target_repo)

    # Repository & Git Status Bar
    col_git1, col_git2, col_git3 = st.columns(3)
    with col_git1:
        st.markdown(f"**Target Directory:** `{target_repo}`")
    with col_git2:
        current_branch = git_manager.get_current_branch() or "Non-Git / Detached"
        st.markdown(f"**Current Branch:** `{current_branch}`")
    with col_git3:
        status_text = "Tracked in Git" if git_manager.is_git_repo else "Not initialized (auto-init available)"
        st.markdown(f"**VCS Status:** `{status_text}`")

    st.markdown("---")

    # Run Remediation Scan button
    if st.button("Scan Repository for Remediations", type="primary") or st.session_state.get("run_remediation_trigger", False):
        st.session_state["run_remediation_trigger"] = False
        with st.spinner("Tier 1 & Tier 2 Subagents inspecting files, dependencies, and credentials..."):
            try:
                report = audit_and_remediate(target_repo, provider=query_provider, embeddings_provider=embedding_provider)
                st.session_state["remediation_report"] = report
            except Exception as e:
                st.error(f"Remediation analysis failed: {e}")

    # Render Remediation Findings and Patches
    if "remediation_report" in st.session_state:
        report = st.session_state["remediation_report"]

        st.markdown(f"**Summary:** {report.summary}")

        if not report.findings:
            st.success("No critical vulnerabilities or hardcoded secrets requiring automated remediation found!")
        else:
            st.markdown(f"#### Actionable Vulnerabilities ({len(report.findings)})")

            patches_by_id = {p.finding_id: p for p in report.patches}

            for idx, finding in enumerate(report.findings):
                badge_class = "badge-critical" if finding.severity == "CRITICAL" else "badge-high"
                patch = patches_by_id.get(finding.id)

                with st.expander(
                    f"[{finding.severity}] {finding.issue_type} in {finding.file_path} (Line {finding.line_number or 'N/A'})",
                    expanded=True if idx == 0 else False,
                ):
                    st.markdown(
                        f'<span class="{badge_class}">{finding.severity}</span> '
                        f'<code>{finding.file_path}</code>',
                        unsafe_allow_html=True
                    )
                    st.write(finding.description)

                    if patch:
                        st.markdown("**Remediation Strategy:**")
                        st.write(patch.explanation)

                        # Side-by-side or stacked diff view
                        st.markdown("**Proposed Code Replacement:**")
                        st.markdown(f"""
<div class="diff-container">
    <div class="diff-del">- {patch.original_snippet}</div>
    <div class="diff-add">+ {patch.replacement_snippet}</div>
</div>
                        """, unsafe_allow_html=True)

                        col_p1, col_p2 = st.columns(2)
                        with col_p1:
                            if patch.env_additions:
                                st.markdown("**.env Additions:**")
                                for k, v in patch.env_additions.items():
                                    st.code(f"{k}={v}", language="bash")
                            if patch.import_additions:
                                st.markdown("**Required Imports:**")
                                for imp in patch.import_additions:
                                    st.code(imp, language="python")

                        with col_p2:
                            if patch.requirements_additions:
                                st.markdown("**Dependency Check (requirements.txt):**")
                                for req in patch.requirements_additions:
                                    st.code(req, language="text")

            # Git Isolation & Apply Section
            st.markdown("---")
            st.markdown("### Apply Patches with Git Branch Isolation")
            st.caption("Creates a dedicated branch, safely updates code and .env, and creates an atomic commit.")

            default_branch = f"audit-fixes-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            branch_col, btn_col = st.columns([2, 1])

            with branch_col:
                isolation_branch = st.text_input(
                    "Isolation Branch Name",
                    value=default_branch,
                    help="Fixes will be committed exclusively to this branch."
                )

            with btn_col:
                st.write("")
                st.write("")
                if st.button("Apply All Fixes to Branch", type="primary"):
                    with st.status("Applying remediation patches...", expanded=True) as status:
                        # Step 1: Create isolation branch
                        st.write(f"Creating Git isolation branch: `{isolation_branch}`")
                        git_manager.create_fix_branch(isolation_branch)

                        # Step 2: Apply patches
                        success_count = 0
                        for patch in report.patches:
                            ok, msg = git_manager.apply_patch(patch)
                            if ok:
                                success_count += 1
                                st.write(f"Applied fix for `{patch.file_path}`")
                            else:
                                st.warning(f"Skipped {patch.file_path}: {msg}")

                        # Step 3: Commit
                        commit_result = git_manager.commit_fixes(
                            branch_name=isolation_branch,
                            message=f"fix(security): remediate {success_count} security issues and extract secrets"
                        )

                        if commit_result.success:
                            status.update(label="Remediation applied and committed successfully!", state="complete", expanded=False)
                            st.session_state["last_commit_result"] = commit_result
                            st.rerun()
                        else:
                            status.update(label="Commit failed", state="error", expanded=True)
                            st.error(commit_result.error_message)

    # Post-Commit Result and Rollback Box
    if "last_commit_result" in st.session_state:
        res = st.session_state["last_commit_result"]
        st.markdown("---")
        st.success(f"Successfully remediated vulnerabilities on branch **`{res.branch_name}`** (Commit: `{res.commit_hash}`)")

        col_rb1, col_rb2 = st.columns([3, 1])
        with col_rb1:
            st.markdown(f"""
- **Modified Files:** {', '.join(res.files_modified) if res.files_modified else 'code files, .env, requirements.txt'}
- **Environment:** Secret entries securely added to `.env` and `.gitignore` updated.
- **Dependencies:** `python-dotenv` verified in `requirements.txt`.
- **Original Branch:** `{res.original_branch}`
            """)

        with col_rb2:
            st.write("")
            if st.button(f"Rollback to '{res.original_branch}'"):
                ok, msg = git_manager.rollback_to_original()
                if ok:
                    st.success(msg)
                    del st.session_state["last_commit_result"]
                    st.rerun()
                else:
                    st.error(msg)
