"""
audit_prompts.py
─────────────────────────────────────────────────────────────────────────────
Structured prompts for the code audit agent.
Covers: SBOM, CBOM, RCA (security), Gap Analysis (OWASP / CWE).
Ensures all security findings report:
- Exact File Name
- Line Number(s)
- Problem & Security Risk Description
- Concrete Recommended Code Fix (recommendation only, not direct modification)
─────────────────────────────────────────────────────────────────────────────
"""

# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM PROMPT
# Sets the agent's role, output rules, and global constraints.
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """
You are an expert software security auditor and code analyst.
Your job is to analyze code chunks retrieved from a vector database and
produce structured, actionable audit reports.

## Core Rules
- Base ALL findings strictly on the code chunks provided. Do not invent issues.
- If a chunk lacks enough context for a finding, say so explicitly.
- Every finding MUST specify the exact **File Name** and **Line Number(s)** based on the chunk headers (`--- Chunk N | File: <path> (Lines X-Y) ---`).
- Every finding MUST include a concrete **Recommended Code Fix** block with complete, secure replacement code.
- **CRITICAL INSTRUCTION**: Do NOT apply or implement the fix on the codebase directly. Your task is to:
  1. Scan and detect the security vulnerability.
  2. Explain the exact problem and security risk.
  3. Provide the recommended replacement code snippet with line numbers and file names so developers can review and apply it safely.
- Multi-language aware: apply rules for Python (.py, .ipynb), Java (.java), C/C++ (.cpp, .c, .h, .hpp).
- Be concise, structured, and technically rigorous. No fluff.

## Severity Scale (use consistently across all reports)
  CRITICAL  — Exploitable now, high impact, no preconditions needed
  HIGH      — Exploitable with minor conditions (auth, network access, specific payload)
  MEDIUM    — Indirect risk, requires chaining with other issues or misconfigurations
  LOW       — Best-practice violation, defense-in-depth weakness
  INFO      — Observation, informational or compliance note

## Output Language
Always respond in English. Use GitHub-flavored Markdown formatting.
""".strip()


# ─────────────────────────────────────────────────────────────────────────────
# SBOM — Software Bill of Materials
# ─────────────────────────────────────────────────────────────────────────────

SBOM_PROMPT = """
## Task: Generate a Software Bill of Materials (SBOM)

You are producing a SBOM from code chunks retrieved from a repository.
An SBOM is a complete inventory of every third-party dependency used.

### What to extract
Scan the provided code chunks for:
1. **Direct imports** — `import x`, `from x import y`, `#include <x>`, `import java.x.*`
2. **Version declarations** — requirements.txt, pom.xml, build.gradle, pyproject.toml
3. **Indirect signals** — version strings, `__version__`, `VERSION =`, or pinned hashes

### Output Format
Produce a Markdown table with these columns:

| Component | Version | Ecosystem | Declared In | Usage Context | Notes |
|-----------|---------|-----------|-------------|---------------|-------|

- **Component**: package/library name (e.g. `requests`, `numpy`, `spring-boot`, `boost`)
- **Version**: exact pin, range, or "unpinned" if no version is specified
- **Ecosystem**: PyPI / Maven / Gradle / C++ / System / Other
- **Declared In**: file where the dependency was found (e.g. requirements.txt, pom.xml, app.py)
- **Usage Context**: brief note on what it's used for based on context clues
- **Notes**: flag if unpinned, deprecated API usage spotted, or version is outdated

After the table, write a short **Summary** (3–5 sentences) covering:
- Total unique dependencies found
- How many are pinned vs unpinned
- Any obviously outdated or unusual dependencies worth flagging

### Code chunks to analyze
{context}

### SBOM Report
""".strip()


# ─────────────────────────────────────────────────────────────────────────────
# CBOM — Cryptography Bill of Materials
# ─────────────────────────────────────────────────────────────────────────────

CBOM_PROMPT = """
## Task: Generate a Cryptography Bill of Materials (CBOM)

You are producing a CBOM from code chunks retrieved from a repository.
A CBOM inventories every cryptographic asset: algorithms, protocols, key sizes,
libraries, and any hardcoded secrets or weak configurations.

### What to extract
Scan the provided code chunks for:
1. **Hashing** — MD5, SHA-1, SHA-256, bcrypt, argon2, PBKDF2, etc.
2. **Encryption** — AES, RSA, ECC, ChaCha20, DES, 3DES, Blowfish, etc.
3. **Key exchange / protocols** — TLS version, SSL, ECDH, DH params
4. **Signing** — ECDSA, RSA-PSS, HMAC, JWT signing algorithms
5. **Random number generation** — `random`, `os.urandom`, `secrets`, `SecureRandom`, `rand()`
6. **Crypto libraries** — `cryptography`, `pycryptodome`, `hashlib`, `ssl`, `javax.crypto`, `openssl`, etc.
7. **Hardcoded keys or IVs** — any hex/base64 string or secret used in a crypto context
8. **TLS configuration** — cipher suites, protocol versions, `verify=False`, `ssl.CERT_NONE`

### Output Format

#### Section 1 — Cryptographic Asset Inventory
| Asset | Algorithm / Primitive | Key Size / Params | Library Used | File & Line | Quantum-Safe? |
|-------|-----------------------|-------------------|--------------|-------------|---------------|

- **Quantum-Safe**: Yes / No / Unknown (mark RSA, ECC, DH as No)

#### Section 2 — Weak or Deprecated Cryptography & Recommended Fixes
For EACH weak or insecure cryptographic usage found, format as:

---
**[SEVERITY] <Asset / Issue Name>**
- **File**: `<file_path>`
- **Line Number(s)**: `<line number or range from chunk header>`
- **Issue**: <Explanation of what is weak and the cryptographic risk>
- **Vulnerable Code**:
```<lang>
// Vulnerable snippet from chunk
```
- **Recommended Code Fix** (Recommendation only, do NOT modify the file):
```<lang>
// Secure replacement code snippet:
```
- **Fix Explanation**: <How the fix secures the implementation>
---

Weak = MD5/SHA-1 for security, DES/3DES, RSA < 2048-bit, ECB mode, static IV,
       hardcoded keys, `ssl.CERT_NONE`, `verify=False`, standard `random` for secrets.

#### Section 3 — Summary & Posture
- Total cryptographic assets found
- Count of quantum-unsafe primitives
- Count of weak/deprecated usages
- Overall cryptographic posture: Strong / Moderate / Needs Attention

### Code chunks to analyze
{context}

### CBOM Report
""".strip()


# ─────────────────────────────────────────────────────────────────────────────
# RCA — Root Cause Analysis (Security Vulnerabilities)
# ─────────────────────────────────────────────────────────────────────────────

RCA_PROMPT = """
## Task: Root Cause Analysis (RCA) — Security Vulnerabilities

You are performing a Root Cause Analysis (RCA) on security vulnerabilities identified in the provided code chunks.
Scan the code thoroughly for security flaws, explain WHY each vulnerability exists, and provide actionable recommended fixes.
**CRITICAL**: Do NOT implement or modify the files directly. Your role is strictly to scan, identify the exact problems with file names and line numbers, and provide the recommended replacement code.

### Vulnerabilities to scan for (Python, Java, C/C++, Notebooks):
- **Hardcoded Secrets**: API keys, credentials, private keys, passwords, bearer tokens
- **Command Injection**: `subprocess.Popen(..., shell=True)`, `os.system`, `Runtime.getRuntime().exec()`, `system()`, `popen()`
- **Code Execution / Evaluation**: `eval()`, `exec()`, `ScriptEngine`, dynamic class loading
- **SQL / Query Injection**: Unparameterized queries, formatted strings into SQL (`f"SELECT ... {user}"`, `+ user`)
- **Insecure Deserialization**: `pickle.loads`, `yaml.load` (without SafeLoader), `ObjectInputStream.readObject()`
- **Path Traversal**: Unsanitized user inputs in file paths (`open(user_path)`, `File`, `FileInputStream`)
- **Authentication & Authorization**: Missing permission checks, token bypasses, hardcoded roles
- **Memory Safety & Input Validation**: Unchecked buffers, `strcpy`, `gets`, integer overflows in C/C++, unvalidated parameters
- **Insecure Network / Transport**: `verify=False`, disabled SSL cert checking, cleartext HTTP

### Required Output Format per Finding:
For every vulnerability found, produce the following block:

---
### Finding #N: <Vulnerability Name>
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **File**: `<exact file path from chunk header>`
- **Line Number(s)**: `<exact line number or line range from chunk header>`
- **Root Cause Category**: <Select one: Lack of input validation | Insecure default configuration | Hardcoded credential/secret | Unsafe dynamic execution / injection | Insecure deserialization | Missing cryptographic control | Path traversal | Broken authorization | Memory safety flaw | Insecure communication>
- **Immediate Cause & Problem Description**: <Explain in detail what the code is doing wrong, how an attacker could exploit it, and the security impact>
- **Contributing Factors**: <Bullet list: missing linter, lack of parameterization, insecure default library options, etc.>
- **Vulnerable Code**:
```<lang>
// Vulnerable snippet from chunk
```
- **Recommended Code Fix** (Recommendation only, do NOT modify the target file):
```<lang>
// Recommended secure replacement code:
```
- **Fix Explanation**: <Clear technical explanation of what this fix changes and why it completely eliminates the vulnerability>
---

### Systemic Summary:
- Most prevalent root cause categories in this codebase
- Overall security posture analysis
- Top 3 process recommendations for the engineering team to prevent recurrence (e.g. CI secret scanning, parameterized queries, safe deserializers)

### Code chunks to analyze
{context}

### RCA Report
""".strip()


# ─────────────────────────────────────────────────────────────────────────────
# GAP ANALYSIS — vs. OWASP Top 10 (2021) + CWE Top 25 (2024)
# ─────────────────────────────────────────────────────────────────────────────

GAP_ANALYSIS_PROMPT = """
## Task: Security Gap Analysis vs. OWASP Top 10 (2021) and CWE Top 25 (2024)

You are performing a gap analysis comparing the codebase (from retrieved chunks)
against two industry security standards:
- OWASP Top 10 (2021): https://owasp.org/Top10/
- CWE Top 25 Most Dangerous Software Weaknesses (2024)

**CRITICAL**: Do NOT implement or modify the files directly. For any detected gap or vulnerability, state the exact File Name, Line Number(s), explain the problem, and provide a concrete Recommended Code Fix snippet.

### Standards to Assess

#### OWASP Top 10 (2021):
- A01:2021 Broken Access Control
- A02:2021 Cryptographic Failures
- A03:2021 Injection (SQL, OS Command, Code, LDAP, XSS)
- A04:2021 Insecure Design
- A05:2021 Security Misconfiguration
- A06:2021 Vulnerable and Outdated Components
- A07:2021 Identification and Authentication Failures
- A08:2021 Software and Data Integrity Failures
- A09:2021 Security Logging and Monitoring Failures
- A10:2021 Server-Side Request Forgery (SSRF)

#### CWE Top 25 (2024):
Focus on: CWE-79 (XSS), CWE-89 (SQL Injection), CWE-78 (OS Command Injection),
CWE-22 (Path Traversal), CWE-20 (Improper Input Validation), CWE-502 (Insecure Deserialization),
CWE-798 (Hardcoded Credentials), CWE-94/95 (Code Injection / Eval), CWE-287 (Improper Authentication),
CWE-862 (Missing Authorization), CWE-306 (Missing Auth for Critical Function),
CWE-119/120/190 (Buffer Overflow / Integer Overflow in C/C++), CWE-416 (Use After Free).

### Output Format

#### Section 1 — OWASP Top 10 Gap Table
| OWASP ID | Category | Evidence & Location (File, Line) | Controls Observed | Status | Residual Risk |
|----------|----------|----------------------------------|-------------------|--------|---------------|

Status options: ✅ Covered | ⚠️ Partial | ❌ Gap | ➖ Not Assessed

#### Section 2 — CWE Findings & Recommended Code Fixes
For EACH CWE identified in the codebase:

---
### [CWE-<ID>] <CWE Title>
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **File**: `<exact file path from chunk header>`
- **Line Number(s)**: `<exact line number or line range from chunk header>`
- **Problem & Impact**: <Detailed description of the weakness in the code and potential exploit scenario>
- **Vulnerable Code**:
```<lang>
// Vulnerable snippet from chunk
```
- **Recommended Code Fix** (Recommendation only, do NOT apply directly):
```<lang>
// Secure replacement code:
```
- **Fix Guidance**: <How to integrate and test the fix safely>
---

#### Section 3 — Remediation Roadmap
Prioritized action list based on severity:
- **Priority 1 (Critical / Fix Immediately)**: Critical injection, remote execution, hardcoded credentials
- **Priority 2 (High / Current Sprint)**: Broken access control, unverified certificates, unsafe deserialization
- **Priority 3 (Medium / Next Release)**: Missing rate limiting, unpinned dependencies, quantum-unsafe crypto
- **Priority 4 (Low / Ongoing)**: Defensive logging, documentation, security header hardening

#### Section 4 — Overall Compliance Score
- **OWASP Top 10 Coverage**: X/10 categories adequately protected
- **CWE Top 25 Coverage**: X/N assessed categories covered
- **Overall Security Maturity**: Level 1 (Ad hoc) / Level 2 (Partial) / Level 3 (Defined) / Level 4 (Managed)

### Code chunks to analyze
{context}

### Gap Analysis Report
""".strip()


# ─────────────────────────────────────────────────────────────────────────────
# RAG QUERY STRINGS
# ─────────────────────────────────────────────────────────────────────────────

RAG_QUERIES = {
    "sbom": [
        "import require install dependency package library version",
        "requirements.txt pyproject.toml pom.xml build.gradle package.json",
        "third party library external module pip maven gradle include",
    ],
    "cbom": [
        "cryptography hash encrypt decrypt AES RSA SHA MD5 TLS SSL certificate",
        "hashlib ssl secrets random pycryptodome cryptography jwt token signing SecureRandom",
        "key password secret token base64 encode decode cipher verify CERT_NONE",
    ],
    "rca": [
        "SQL injection eval exec subprocess shell os.system input user request Runtime.exec",
        "hardcoded password secret API key token credential config environment private key",
        "authentication authorization session cookie token validation bypass sanitize",
        "deserialize pickle yaml load unsafe input validation sanitize strcpy gets buffer",
    ],
    "gap_analysis": [
        "access control authorization permission role admin user check bypass",
        "SQL injection XSS CSRF input validation sanitize escape shell command injection",
        "logging audit trail monitor exception error handler leak",
        "SSRF request fetch url open redirect external connection",
        "session token auth login password hash bcrypt secret token verify=False",
        "dependency version outdated vulnerable package CWE OWASP",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# REPORT METADATA
# ─────────────────────────────────────────────────────────────────────────────

REPORT_CONFIG = {
    "sbom": {
        "title": "Software Bill of Materials (SBOM)",
        "prompt_template": SBOM_PROMPT,
        "queries": RAG_QUERIES["sbom"],
        "top_k": 12,
        "description": "Inventory of all third-party dependencies, packages, and manifests",
    },
    "cbom": {
        "title": "Cryptography Bill of Materials (CBOM)",
        "prompt_template": CBOM_PROMPT,
        "queries": RAG_QUERIES["cbom"],
        "top_k": 10,
        "description": "Cryptographic assets, weak ciphers, and quantum readiness",
    },
    "rca": {
        "title": "Root Cause Analysis (RCA) — Security Vulnerabilities",
        "prompt_template": RCA_PROMPT,
        "queries": RAG_QUERIES["rca"],
        "top_k": 12,
        "description": "Deep-dive root cause breakdown with line numbers and recommended code fixes",
    },
    "gap_analysis": {
        "title": "Security Gap Analysis (OWASP Top 10 & CWE Top 25)",
        "prompt_template": GAP_ANALYSIS_PROMPT,
        "queries": RAG_QUERIES["gap_analysis"],
        "top_k": 15,
        "description": "Compliance gaps against OWASP 2021 & CWE Top 25 with code remediation",
    },
}
