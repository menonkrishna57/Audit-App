# Code Audit & Remediation Platform

## Prerequisites
- **Python Virtual Environment**: Use `.venv` (`.\.venv\Scripts\Activate.ps1`).
- **Gemini API**: Ensure `GOOGLE_API_KEY` or `GEMINI_API_KEY` is in your `.env` file (runs `gemini-3.8-flash` via `google-genai`).
- **Qdrant Vector Database**: Optional for semantic vector search (`docker run -p 6333:6333 qdrant/qdrant`).

---

## 1. Interactive Streamlit Dashboard
Launch the unified audit and remediation dashboard:

```powershell
.\.venv\Scripts\streamlit run app.py
```

### Dashboard Capabilities:
- **Tab 1: Ingestion & Indexing**: Select repo path and index code into Qdrant.
- **Tab 2: Audit Reports**: Run SBOM, CBOM, RCA, and OWASP Gap Analysis reports powered by `gemini-3.8-flash`.
- **Tab 3: Remediation & Fixes (1-Click Apply)**:
  - Detects hardcoded secrets, API keys, credentials, and code flaws.
  - Generates unified diffs (`os.getenv(...)` replacement, `.env` entries, `requirements.txt` updates).
  - Isolates fixes on a dedicated Git branch (e.g., `audit-fixes-20261022_160000`).
  - Includes a 1-click **Rollback to Original Branch** button.

---

## 2. Headless CLI & Jenkins CI/CD Automation

Run automated audit and remediation checks directly in CI/CD pipelines (Jenkins, GitHub Actions):

```powershell
# Standard run with Gemini 3.8 Flash
.\.venv\Scripts\python agent.py --provider gemini

# Headless CI mode for Jenkins: exits with code 1 if CRITICAL vulnerabilities exist
.\.venv\Scripts\python agent.py --ci --provider gemini --fail-on CRITICAL --target .
```

### Jenkinsfile Pipeline Example:
```groovy
pipeline {
    agent any
    stages {
        stage('Security Audit & Remediation Check') {
            steps {
                sh '.venv/bin/python agent.py --ci --provider gemini --fail-on CRITICAL --target .'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/*.json, reports/*.md', fingerprint: true
                }
            }
        }
    }
}
```

---

## 3. Ingestion & Vector Search (Optional)

```powershell
# Index codebase chunks into Qdrant
.\.venv\Scripts\python ingest.py /path/to/repo --embeddings google
```

---

## 4. Running Verification Tests

Run the remediation test suite to verify secret extraction, `.env` injection, and Git isolation:

```powershell
.\.venv\Scripts\python tests/test_remediation.py
```