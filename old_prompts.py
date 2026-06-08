AUDIT_CATEGORIES = {
    "security": {
        # Specific tokens that appear in genuinely risky code, not generic descriptions
        "query": "os.system subprocess.call eval exec hardcoded password secret token api_key JWT SECRET_KEY sql cursor.execute %s format injection pickle.loads yaml.load",
        "instruction": """You are a security auditor. Analyze the FULL code chunks below for:
- Hardcoded credentials, API keys, tokens, or secrets (look for assignment to variables named key, secret, token, password, auth)
- Shell injection: os.system(), subprocess with shell=True, or f-string passed to exec/eval
- SQL injection: raw .execute() calls using string formatting or concatenation instead of parameterized queries
- Unsafe deserialization: pickle.loads(), yaml.load() without Loader=
- Missing authentication/authorization checks on endpoints
For each issue: state the file name, the exact line or function name, severity (Critical/High/Medium/Low), and a specific recommended fix.
If no issues are found, state which patterns you checked for and confirmed safe."""
    },
    "code_quality": {
        # Targets tokens that appear in long, complex, deeply nested first-party code
        "query": "def __init__ self for while if elif else try except class return raise TypeError ValueError IndexError",
        "instruction": """You are a code quality reviewer. Analyze the FULL function and class bodies below for:
- Functions or methods that appear to have many responsibilities (god functions)
- Hardcoded numeric literals used as thresholds, limits, or sizes (e.g., 512, 100, 3) — flag these as magic numbers that should be named constants
- Deeply nested logic: for/while loops with 3+ levels of if/else inside them
- Broad except clauses that swallow all errors silently (e.g., `except Exception: pass`)
- Missing try/except around file I/O, network calls, or database operations
For each issue: state the file name, the function or class name, describe the specific problem, and suggest a concrete refactor."""
    },
    "documentation": {
        # Targets function/class definitions which are most likely to be missing docs
        "query": "def class async def staticmethod classmethod property return type hint annotation",
        "instruction": """You are a documentation reviewer. Analyze the FULL function and class definitions below for:
- Public functions or methods (not starting with _) that are completely missing a docstring
- Any function with more than 2 parameters that has no type hints on its signature
- Classes missing a class-level docstring explaining its purpose
- Complex logic blocks (more than 10 lines of computation) with zero inline comments explaining the intent
For each issue: state the file name, the exact function or class name, and explain what documentation is missing."""
    },
    "dependencies": {
        # Targets import statements and requirements files directly
        "query": "import from requirements install_requires setup.py pyproject.toml package version == >= <= deprecated",
        "instruction": """You are a dependency auditor. Analyze the code and configuration chunks below for:
- Imports of known deprecated or high-risk modules (e.g., telnetlib, imp, distutils, cgi, crypt, pipes)
- Unused imports: any `import X` or `from X import Y` where Y does not appear to be used in the visible code
- Dependencies in requirements files pinned with `>=` or no version pin at all (prefer `==` for reproducibility)
- Direct use of `requests` without timeout parameters (a common reliability bug)
Note any patterns across multiple files."""
    },
}

# --- Duplicate Logic Detection (Static Analysis) ---
# This is handled separately in agent.py via find_duplicate_functions(),
# because RAG cannot surface cross-file similarity. The LLM sees full
# function signatures extracted directly from source files.
DUPLICATE_INSTRUCTION = """You are a code quality reviewer specializing in identifying duplicate logic.
Below is a list of all function and method definitions found across the codebase, grouped by file.
Identify any functions that appear to be doing the same thing under different names, or that have near-identical logic.
For each suspected duplicate pair: state both file names and function names, explain what they share, and recommend which one to keep or how to merge them into a shared utility.
If no duplicates are found, confirm that the function names appear to have distinct responsibilities."""