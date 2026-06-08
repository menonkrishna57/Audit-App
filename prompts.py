"""
audit_prompts.py
─────────────────────────────────────────────────────────────────────────────
Structured prompts for the code audit agent.
Covers: SBOM, CBOM, RCA (security), Gap Analysis (OWASP / CWE).

Drop these into your existing agent.py AUDIT_CATEGORIES dict,
or use SYSTEM_PROMPT as a system message in a multi-turn agent setup.
─────────────────────────────────────────────────────────────────────────────
"""

# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM PROMPT
# Sets the agent's role, output rules, and global constraints.
# Use as the `system` parameter in your LLM call.
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """
You are an expert software security auditor and code analyst.
Your job is to analyze code chunks retrieved from a vector database and
produce structured, actionable audit reports.

## Core Rules
- Base ALL findings strictly on the code chunks provided. Do not invent issues.
- If a chunk lacks enough context for a finding, say so explicitly.
- Every finding must include: file reference, a description, severity, and a fix.
- Use the exact output format specified in each task. Do not add extra sections.
- Language-aware: apply Python-specific rules for .py files, JS rules for .js/.ts,
  and general rules for unknown file types.
- Be concise. One finding = one clear paragraph or table row. No padding.

## Severity Scale (use consistently across all reports)
  CRITICAL  — Exploitable now, no preconditions needed
  HIGH      — Exploitable with minor conditions (auth, network access)
  MEDIUM    — Indirect risk, requires chaining with other issues
  LOW       — Best-practice violation, not directly exploitable
  INFO      — Observation, no immediate risk

## Output Language
Always respond in English. Use Markdown formatting.
""".strip()


# ─────────────────────────────────────────────────────────────────────────────
# SBOM — Software Bill of Materials
# What it does: inventories all third-party libraries, packages, and versions
# found in the code (imports, requirements, lock files, inline version strings).
# ─────────────────────────────────────────────────────────────────────────────

SBOM_PROMPT = """
## Task: Generate a Software Bill of Materials (SBOM)

You are producing a SBOM from code chunks retrieved from a repository.
An SBOM is a complete inventory of every third-party dependency used.

### What to extract
Scan the provided code chunks for:
1. **Direct imports** — `import x`, `from x import y`, `require('x')`, `import x from 'x'`
2. **Version declarations** — anything in requirements.txt, pyproject.toml, package.json,
   Pipfile, setup.py, pom.xml, build.gradle, go.mod, Cargo.toml, or inline comments
3. **Indirect signals** — version strings, `__version__`, `VERSION =`, or pinned hashes

### Output Format
Produce a Markdown table with these columns:

| Component | Version | Ecosystem | Declared In | Usage Context | Notes |
|-----------|---------|-----------|-------------|---------------|-------|

- **Component**: package/library name (e.g. `requests`, `numpy`, `flask`)
- **Version**: exact pin, range, or "unpinned" if no version is specified
- **Ecosystem**: PyPI / npm / Maven / Cargo / Go / Other
- **Declared In**: file where the dependency was found (e.g. requirements.txt, app.py)
- **Usage Context**: brief note on what it's used for based on context clues
- **Notes**: flag if unpinned, deprecated API usage spotted, or version is very old

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
# What it does: inventories all cryptographic primitives, algorithms, key sizes,
# protocols, and libraries used — critical for compliance and quantum readiness.
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
5. **Random number generation** — `random`, `os.urandom`, `secrets`, Math.random()
6. **Crypto libraries** — `cryptography`, `pycryptodome`, `hashlib`, `ssl`,
   `crypto` (Node), `javax.crypto`, `openssl`, `nacl`, etc.
7. **Hardcoded keys or IVs** — any hex/base64 string used in a crypto context
8. **TLS configuration** — cipher suites, protocol versions, cert validation flags

### Output Format

#### Section 1 — Cryptographic Asset Inventory
| Asset | Algorithm / Primitive | Key Size / Params | Library Used | File | Quantum-Safe? |
|-------|-----------------------|-------------------|--------------|------|---------------|

- **Quantum-Safe**: Yes / No / Unknown (mark RSA, ECC, DH as No)

#### Section 2 — Weak or Deprecated Cryptography
List each weak finding as:
```
[SEVERITY] File: <file>
Issue: <what is weak and why>
Fix: <concrete replacement>
```
Weak = MD5/SHA-1 for security, DES/3DES, RSA < 2048-bit, ECB mode, static IV,
       hardcoded keys, `ssl.CERT_NONE`, `verify=False`, `random` for secrets.

#### Section 3 — Summary
- Total cryptographic assets found
- Count of quantum-unsafe primitives
- Count of weak/deprecated usages
- Overall cryptographic posture: Strong / Moderate / Weak

### Code chunks to analyze
{context}

### CBOM Report
""".strip()


# ─────────────────────────────────────────────────────────────────────────────
# RCA — Root Cause Analysis (Security Vulnerabilities)
# What it does: for each vulnerability found in the audit, traces WHY it exists
# — the root cause category, contributing factors, and systemic patterns.
# ─────────────────────────────────────────────────────────────────────────────

RCA_PROMPT = """
## Task: Root Cause Analysis (RCA) — Security Vulnerabilities

You are performing an RCA on security vulnerabilities identified in code chunks.
Do not just list vulnerabilities — explain WHY each one exists and what systemic
pattern it reveals.

### RCA Framework to apply
For each vulnerability, determine:
1. **Immediate Cause** — the exact line/pattern that introduces the risk
2. **Root Cause Category** — pick the closest match:
   - Lack of input validation
   - Insecure default configuration
   - Broken authentication / authorization logic
   - Unsafe dependency or third-party trust
   - Missing cryptographic control
   - Improper error handling / information leakage
   - Race condition / concurrency flaw
   - Insecure deserialization
   - Developer misuse of a secure API
   - Missing security control (no logging, no rate limit, etc.)
3. **Contributing Factors** — e.g. no code review evidence, missing tests,
   use of deprecated API, pressure to ship, lack of security linting
4. **Systemic Pattern** — does this appear across multiple files/functions?
   Is it a one-off mistake or a repeated anti-pattern in the codebase?

### Output Format
For each vulnerability found, produce:

---
**Finding #N**
- **Vulnerability**: <name, e.g. SQL Injection, Hardcoded Secret>
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **File & Location**: <file path, function name if visible>
- **Immediate Cause**: <exact code pattern or construct responsible>
- **Root Cause Category**: <category from the list above>
- **Contributing Factors**: <bullet list>
- **Systemic Pattern**: <is this isolated or repeated? Evidence from chunks>
- **Recommended Fix**: <concrete, actionable — include a corrected code snippet if possible>
---

After all findings, write a **Systemic Summary**:
- Which root cause categories appear most frequently?
- What does this say about the team's security posture?
- Top 3 process recommendations (e.g. add bandit to CI, enforce input validation helpers)

### Code chunks to analyze
{context}

### RCA Report
""".strip()


# ─────────────────────────────────────────────────────────────────────────────
# GAP ANALYSIS — vs. OWASP Top 10 + CWE Top 25
# What it does: maps findings (and absences of controls) to OWASP/CWE entries,
# rates current coverage, and produces a remediation roadmap.
# ─────────────────────────────────────────────────────────────────────────────

GAP_ANALYSIS_PROMPT = """
## Task: Security Gap Analysis vs. OWASP Top 10 (2021) and CWE Top 25 (2024)

You are performing a gap analysis comparing the codebase (from retrieved chunks)
against two industry security standards:
- OWASP Top 10 (2021): https://owasp.org/Top10/
- CWE Top 25 Most Dangerous Software Weaknesses (2024)

### Instructions
For EACH of the 10 OWASP categories and the top CWE entries below, assess:
1. **Evidence Found** — does the code show signs of this vulnerability class?
2. **Evidence of Controls** — does the code show mitigations? (validation,
   sanitization, auth checks, parameterized queries, etc.)
3. **Coverage Status** — Covered / Partial / Gap / Not Assessed
4. **Risk Level** — given what you found, what is the residual risk?

### OWASP Top 10 (2021) — assess all 10
A01 Broken Access Control
A02 Cryptographic Failures
A03 Injection (SQL, command, LDAP, XSS)
A04 Insecure Design
A05 Security Misconfiguration
A06 Vulnerable and Outdated Components
A07 Identification and Authentication Failures
A08 Software and Data Integrity Failures
A09 Security Logging and Monitoring Failures
A10 Server-Side Request Forgery (SSRF)

### CWE Top 25 — assess where evidence exists in the chunks
Focus on: CWE-79 (XSS), CWE-89 (SQL Injection), CWE-22 (Path Traversal),
CWE-78 (OS Command Injection), CWE-20 (Improper Input Validation),
CWE-502 (Deserialization), CWE-287 (Improper Authentication),
CWE-862 (Missing Authorization), CWE-306 (Missing Auth for Critical Function),
CWE-798 (Hardcoded Credentials), CWE-77 (Command Injection),
CWE-190 (Integer Overflow), CWE-416 (Use After Free — if applicable)

### Output Format

#### Section 1 — OWASP Top 10 Gap Table
| OWASP ID | Category | Evidence of Vulnerability | Evidence of Controls | Status | Residual Risk |
|----------|----------|--------------------------|----------------------|--------|---------------|

Status options: ✅ Covered | ⚠️ Partial | ❌ Gap | ➖ Not Assessed

#### Section 2 — CWE Findings Table
| CWE ID | Name | Found In | Severity | Status |
|--------|------|----------|----------|--------|

Only include CWEs where evidence (present or absent) was found in the chunks.

#### Section 3 — Remediation Roadmap
Prioritized action list. Format each item as:

**[Priority N] <Action title>**
- Addresses: <OWASP ID(s) and/or CWE ID(s)>
- Effort: Low / Medium / High
- What to do: <specific, concrete steps>

Priority 1 = fix immediately (CRITICAL gaps)
Priority 2 = fix in current sprint (HIGH gaps)
Priority 3 = fix in next release (MEDIUM gaps)
Priority 4 = track and improve (LOW / process gaps)

#### Section 4 — Overall Compliance Score
Rate the codebase on each standard:
- OWASP Top 10 Coverage: X/10 categories adequately covered
- CWE Top 25 Coverage: X/N assessed categories covered
- Overall Security Maturity: Level 1 (Ad hoc) / Level 2 (Partial) /
  Level 3 (Defined) / Level 4 (Managed) [use OWASP SAMM scale]

### Code chunks to analyze
{context}

### Gap Analysis Report
""".strip()


# ─────────────────────────────────────────────────────────────────────────────
# RAG QUERY STRINGS
# Optimised similarity search queries per report type.
# Pass these to vectorstore.similarity_search(query, k=TOP_K)
# ─────────────────────────────────────────────────────────────────────────────

RAG_QUERIES = {
    "sbom": [
        "import require install dependency package library version",
        "requirements.txt pyproject.toml package.json setup.py Pipfile go.mod Cargo.toml",
        "third party library external module pip npm maven gradle",
    ],
    "cbom": [
        "cryptography hash encrypt decrypt AES RSA SHA MD5 TLS SSL certificate",
        "hashlib ssl secrets random pycryptodome cryptography jwt token signing",
        "key password secret token base64 encode decode cipher verify",
    ],
    "rca": [
        "SQL injection eval exec subprocess shell os.system input user request",
        "hardcoded password secret API key token credential config environment",
        "authentication authorization session cookie token validation bypass",
        "deserialize pickle yaml load unsafe input validation sanitize",
    ],
    "gap_analysis": [
        "access control authorization permission role admin user check",
        "SQL injection XSS CSRF input validation sanitize escape",
        "logging audit trail monitor exception error handler",
        "SSRF request fetch url open redirect external",
        "session token auth login password hash bcrypt",
        "dependency version outdated vulnerable package",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# REPORT METADATA
# Used by agent.py to drive report generation loop.
# ─────────────────────────────────────────────────────────────────────────────

REPORT_CONFIG = {
    "sbom": {
        "title": "Software Bill of Materials (SBOM)",
        "prompt_template": SBOM_PROMPT,
        "queries": RAG_QUERIES["sbom"],
        "top_k": 12,           # needs broad coverage across all files
        "description": "Inventory of all third-party dependencies and packages",
    },
    "cbom": {
        "title": "Cryptography Bill of Materials (CBOM)",
        "prompt_template": CBOM_PROMPT,
        "queries": RAG_QUERIES["cbom"],
        "top_k": 10,
        "description": "Inventory of all cryptographic assets and weak crypto usage",
    },
    "rca": {
        "title": "Root Cause Analysis — Security Vulnerabilities",
        "prompt_template": RCA_PROMPT,
        "queries": RAG_QUERIES["rca"],
        "top_k": 10,
        "description": "Root cause breakdown of each security vulnerability found",
    },
    "gap_analysis": {
        "title": "Security Gap Analysis (OWASP Top 10 / CWE Top 25)",
        "prompt_template": GAP_ANALYSIS_PROMPT,
        "queries": RAG_QUERIES["gap_analysis"],
        "top_k": 15,           # needs widest retrieval for full coverage
        "description": "Compliance gap assessment against OWASP 2021 and CWE Top 25",
    },
}