import os
import re
import json
import difflib
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

from dotenv import load_dotenv
from google import genai
from google.genai import types

from .models import Finding, RemediationPatch, AuditReport

load_dotenv()

# Regex patterns for deterministic secret and credential detection
SECRET_PATTERNS = [
    # Google API Key
    (r'(?:AIza[0-9A-Za-z-_]{35}|AQ\.[0-9A-Za-z-_]{40,})', "GOOGLE_API_KEY", "Google Cloud / Gemini API Key"),
    # Generic API Key / Secret assignments
    (r'(?i)(api[_-]?key|secret[_-]?key|token|auth[_-]?token|password)\s*=\s*["\']([a-zA-Z0-9_\-\.]{12,})["\']', "GENERIC_SECRET", "Hardcoded API Key / Token"),
    # Jina API key
    (r'jina_[a-zA-Z0-9]{32,}', "JINA_API_KEY", "Jina Embeddings API Key"),
    # OpenAI key format
    (r'sk-[a-zA-Z0-9]{32,}', "OPENAI_API_KEY", "OpenAI API Key"),
    # AWS Access Key ID
    (r'AKIA[0-9A-Z]{16}', "AWS_ACCESS_KEY_ID", "AWS Access Key ID"),
]


class RemediationEngine:
    """Core engine orchestrating Gemini 3.8 Flash, code inspection, and remediation."""

    def __init__(self, model_name: str = "gemini-3.8-flash"):
        self.model_name = model_name
        self.api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.client = None
        if self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
            except Exception as e:
                print(f"[RemediationEngine] Error initializing genai.Client: {e}")

    def call_gemini(self, prompt: str, system_instruction: Optional[str] = None) -> str:
        """Call Gemini 3.8 Flash using the official google-genai SDK."""
        if not self.client:
            raise ValueError("GEMINI_API_KEY or GOOGLE_API_KEY not configured.")

        # Using client.models.generate_content or interactions
        try:
            config = types.GenerateContentConfig(
                temperature=0.1,
                system_instruction=system_instruction,
            )
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=config,
            )
            if response and response.text:
                return response.text
        except Exception as e:
            # Fallback to interactions API if supported
            try:
                interaction = self.client.interactions.create(
                    model=self.model_name,
                    input=prompt,
                )
                return interaction.output_text or ""
            except Exception as inner_e:
                raise RuntimeError(f"Gemini API invocation failed: {e}; {inner_e}")
        return ""


class AuditorAgent:
    """Tier 1: Analyzes RAG chunks or files, extracts findings with precise locations."""

    def __init__(self, engine: Optional[RemediationEngine] = None):
        self.engine = engine or RemediationEngine()

    def scan_file_for_secrets(self, file_path: Path, repo_root: Path) -> List[Finding]:
        """Deterministic scanner to guarantee secrets are flagged with exact line numbers."""
        findings = []
        try:
            rel_path = str(file_path.relative_to(repo_root))
            # Skip .env and files that should hold secrets
            if file_path.name == ".env" or ".env." in file_path.name:
                return []

            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()

            for line_idx, line in enumerate(lines, start=1):
                # Ignore comment lines
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue

                for pattern, secret_type, desc in SECRET_PATTERNS:
                    match = re.search(pattern, line)
                    if match:
                        matched_str = match.group(0)
                        # Avoid matching placeholders like "your_api_key_here"
                        if "your_" in matched_str.lower() or "example" in matched_str.lower():
                            continue

                        finding_id = f"SEC-{len(findings)+1:03d}"
                        findings.append(
                            Finding(
                                id=finding_id,
                                file_path=rel_path,
                                issue_type="HARDCODED_SECRET",
                                severity="CRITICAL",
                                description=f"Found hardcoded {desc} on line {line_idx}.",
                                code_snippet=line.strip(),
                                line_number=line_idx,
                                recommendation=(
                                    f"Extract secret into environment variable and load using "
                                    f"python-dotenv / os.getenv."
                                ),
                            )
                        )
                        break
        except Exception as e:
            print(f"[AuditorAgent] Error scanning {file_path}: {e}")
        return findings

    def parse_findings_from_audit(
        self, audit_text: str, repo_root: Path
    ) -> List[Finding]:
        """Extract structured findings from Gemini audit report text."""
        findings = []
        # First: scan files directly for guaranteed secret catches
        if repo_root.exists() and repo_root.is_dir():
            for p in repo_root.rglob("*"):
                if p.is_file() and p.suffix in {".py", ".js", ".ts", ".json", ".yaml", ".yml"}:
                    # Skip git and venv
                    if any(part in {".git", ".venv", "venv", "__pycache__", "node_modules"} for part in p.parts):
                        continue
                    findings.extend(self.scan_file_for_secrets(p, repo_root))

        # Second: query Gemini to extract other high/critical security findings
        prompt = f"""
You are a senior security auditor. Below is the text of a code audit report.
Extract up to 5 critical and high-severity security vulnerabilities that have concrete code fixes.

Audit Report:
{audit_text[:6000]}

Return ONLY a valid JSON list of objects matching this schema:
[
  {{
    "id": "VULN-001",
    "file_path": "path/to/file.py",
    "issue_type": "SQL_INJECTION", // or HARDCODED_SECRET, UNSAFE_DESERIALIZATION, etc.
    "severity": "CRITICAL", // or HIGH, MEDIUM
    "description": "Short description of the bug",
    "code_snippet": "vulnerable snippet",
    "line_number": 12, // integer or null
    "recommendation": "How to fix it"
  }}
]
Do not wrap in markdown or backticks, just return raw JSON.
"""
        try:
            if self.engine and self.engine.client:
                res = self.engine.call_gemini(prompt)
                clean_json = res.strip()
                if clean_json.startswith("```"):
                    clean_json = re.sub(r"^```[a-zA-Z]*\n?", "", clean_json)
                    clean_json = re.sub(r"\n?```$", "", clean_json)
                parsed = json.loads(clean_json)
                for item in parsed:
                    # Check if file exists in repo before adding
                    fp = repo_root / item.get("file_path", "")
                    if fp.exists():
                        findings.append(Finding(**item))
        except Exception as e:
            # Fall back to regex-detected findings
            pass

        # Deduplicate findings by (file_path, line_number)
        unique_findings = []
        seen = set()
        for f in findings:
            key = (f.file_path, f.line_number, f.issue_type)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings


class FixerSubagent:
    """Tier 2: Inspects target files on disk, requirements, and .env to build atomic patches."""

    def __init__(self, engine: Optional[RemediationEngine] = None):
        self.engine = engine or RemediationEngine()

    def generate_patch(self, finding: Finding, repo_root: Path) -> Optional[RemediationPatch]:
        """Construct a validated RemediationPatch for a finding."""
        target_file = repo_root / finding.file_path
        if not target_file.exists():
            return None

        file_content = target_file.read_text(encoding="utf-8", errors="ignore")

        if finding.issue_type == "HARDCODED_SECRET":
            return self._generate_secret_patch(finding, target_file, file_content, repo_root)
        else:
            return self._generate_general_patch(finding, target_file, file_content, repo_root)

    def _generate_secret_patch(
        self, finding: Finding, target_file: Path, file_content: str, repo_root: Path
    ) -> RemediationPatch:
        """Deterministic, safe secret extraction to .env and os.getenv."""
        # Find the line containing the secret snippet
        snippet_line = finding.code_snippet.strip()
        lines = file_content.splitlines()

        matched_line = None
        for line in lines:
            if snippet_line in line or line.strip() == snippet_line:
                matched_line = line
                break

        if not matched_line:
            matched_line = snippet_line

        # Detect the secret value
        secret_value = ""
        var_name = "API_KEY"

        # Match key=val assignment
        assign_match = re.search(r'([A-Za-z0-9_]+)\s*=\s*["\']([^"\']+)["\']', matched_line)
        if assign_match:
            detected_key = assign_match.group(1).upper()
            secret_value = assign_match.group(2)
            var_name = detected_key if "KEY" in detected_key or "TOKEN" in detected_key or "SECRET" in detected_key else f"{detected_key}_KEY"
        else:
            # Try to grab quoted secret
            val_match = re.search(r'["\']([a-zA-Z0-9_\-\.]{12,})["\']', matched_line)
            if val_match:
                secret_value = val_match.group(1)
                var_name = "SERVICE_API_KEY"

        # Format replacement line
        if assign_match:
            var_lhs = assign_match.group(1)
            # Indentation
            indent = matched_line[:len(matched_line) - len(matched_line.lstrip())]
            replacement_line = f'{indent}{var_lhs} = os.getenv("{var_name}")'
        else:
            replacement_line = matched_line.replace(f'"{secret_value}"', f'os.getenv("{var_name}")')
            replacement_line = replacement_line.replace(f"'{secret_value}'", f'os.getenv("{var_name}")')

        # Check required imports
        import_additions = []
        if "import os" not in file_content and "from os import" not in file_content:
            import_additions.append("import os")
        if "load_dotenv" not in file_content:
            import_additions.append("from dotenv import load_dotenv\nload_dotenv()")

        # Generate unified diff
        diff_lines = list(
            difflib.unified_diff(
                [matched_line + "\n"],
                [replacement_line + "\n"],
                fromfile=f"a/{finding.file_path}",
                tofile=f"b/{finding.file_path}",
            )
        )
        unified_diff = "".join(diff_lines)

        return RemediationPatch(
            finding_id=finding.id,
            file_path=finding.file_path,
            original_snippet=matched_line,
            replacement_snippet=replacement_line,
            unified_diff=unified_diff,
            env_additions={var_name: secret_value},
            requirements_additions=["python-dotenv>=1.0.0"],
            import_additions=import_additions,
            explanation=(
                f"Extracted hardcoded secret into environment variable '{var_name}', "
                f"replaced literal string with os.getenv('{var_name}'), loaded .env via "
                f"python-dotenv, and updated requirements.txt."
            ),
        )

    def _generate_general_patch(
        self, finding: Finding, target_file: Path, file_content: str, repo_root: Path
    ) -> Optional[RemediationPatch]:
        """Use Gemini 3.8 Flash to formulate a precise code patch for other vulnerabilities."""
        prompt = f"""
You are a senior software security engineer generating a code patch.
File: {finding.file_path}
Vulnerability: {finding.issue_type} ({finding.severity})
Description: {finding.description}
Vulnerable Snippet:
```python
{finding.code_snippet}
```

Surrounding File Content:
```python
{file_content[:3000]}
```

Provide the exact replacement to fix this issue safely.
Return ONLY valid JSON matching this schema:
{{
  "original_snippet": "exact lines to replace from the file",
  "replacement_snippet": "safe replacement lines",
  "requirements_additions": [], // list of package strings if new dependencies needed
  "import_additions": [], // list of import statements if needed
  "explanation": "Why this fixes the security flaw"
}}
"""
        try:
            if not self.engine.client:
                return None
            res = self.engine.call_gemini(prompt)
            clean_json = res.strip()
            if clean_json.startswith("```"):
                clean_json = re.sub(r"^```[a-zA-Z]*\n?", "", clean_json)
                clean_json = re.sub(r"\n?```$", "", clean_json)
            data = json.loads(clean_json)

            orig = data["original_snippet"]
            rep = data["replacement_snippet"]

            diff_lines = list(
                difflib.unified_diff(
                    orig.splitlines(keepends=True),
                    rep.splitlines(keepends=True),
                    fromfile=f"a/{finding.file_path}",
                    tofile=f"b/{finding.file_path}",
                )
            )

            return RemediationPatch(
                finding_id=finding.id,
                file_path=finding.file_path,
                original_snippet=orig,
                replacement_snippet=rep,
                unified_diff="".join(diff_lines),
                requirements_additions=data.get("requirements_additions", []),
                import_additions=data.get("import_additions", []),
                explanation=data.get("explanation", ""),
            )
        except Exception as e:
            print(f"[FixerSubagent] Error generating general patch: {e}")
            return None
