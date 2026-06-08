AUDIT_CATEGORIES = {
    "security": {
        "query": "hardcoded secrets API keys passwords SQL injection eval exec subprocess shell injection unsafe deserialization",
        "instruction": """You are a security auditor. Analyze the code chunks below for:
- Hardcoded credentials or secrets
- Injection vulnerabilities (SQL, shell, prompt)
- Unsafe use of eval/exec
- Insecure deserialization
- Missing input validation
For each issue: state the file, line hint, severity (Critical/High/Medium/Low), and recommended fix."""
    },
    "code_quality": {
        "query": "god class long method duplicate code magic number deep nesting no error handling complex logic",
        "instruction": """You are a code quality reviewer. Analyze the code chunks below for:
- Functions longer than 50 lines
- Deep nesting (4+ levels)
- Duplicate or near-duplicate logic
- Magic numbers/strings without constants
- Missing error handling
- Overly complex conditionals
For each issue: state the file, describe the problem, and suggest a refactor."""
    },
    "documentation": {
        "query": "missing docstring no comments complex function undocumented class public API no type hints",
        "instruction": """You are a documentation reviewer. Analyze the code chunks below for:
- Public functions/classes missing docstrings
- Missing type hints on function signatures
- Complex logic with no inline comments
- Undocumented parameters or return values
For each issue: state the file and function, explain what's missing."""
    },
    "dependencies": {
        "query": "import require version pinned outdated library deprecated package unused import",
        "instruction": """You are a dependency auditor. Analyze the code chunks below for:
- Unpinned or loosely pinned dependencies
- Deprecated library usage
- Unused imports
- Known-risky packages
Note any patterns across files."""
    },
}