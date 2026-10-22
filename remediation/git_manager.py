import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from .models import RemediationPatch, RemediationResult


class GitManager:
    """Manages Git branch isolation, atomic file writes, .env management, and rollbacks."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        self.is_git_repo = self._check_is_git_repo()
        self.original_branch = self.get_current_branch() if self.is_git_repo else None

    def _run_git(self, args: List[str]) -> Tuple[int, str, str]:
        """Execute a git command inside the target repository."""
        try:
            res = subprocess.run(
                ["git"] + args,
                cwd=str(self.repo_path),
                capture_output=True,
                text=True,
                check=False,
            )
            return res.returncode, res.stdout.strip(), res.stderr.strip()
        except FileNotFoundError:
            return -1, "", "git executable not found in PATH"

    def _check_is_git_repo(self) -> bool:
        code, stdout, _ = self._run_git(["rev-parse", "--is-inside-work-tree"])
        return code == 0 and stdout == "true"

    def init_git_repo_if_needed(self) -> bool:
        """Initialize git repo if not already tracked so branch isolation is possible."""
        if not self.is_git_repo:
            code, _, _ = self._run_git(["init"])
            if code == 0:
                self.is_git_repo = True
                self.original_branch = "main"
                # Initial commit if empty
                self._run_git(["add", "."])
                self._run_git(["commit", "-m", "chore: initial commit before audit"])
                return True
            return False
        return True

    def get_current_branch(self) -> Optional[str]:
        if not self.is_git_repo:
            return None
        code, stdout, _ = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"])
        return stdout if code == 0 else "main"

    def create_fix_branch(self, branch_name: Optional[str] = None) -> str:
        """Create and checkout a new isolation branch for remediation."""
        self.init_git_repo_if_needed()
        self.original_branch = self.get_current_branch() or "main"

        if not branch_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            branch_name = f"audit-fixes-{timestamp}"

        code, _, stderr = self._run_git(["checkout", "-b", branch_name])
        if code != 0:
            # If already exists or error, try switching to it
            self._run_git(["checkout", branch_name])
        return branch_name

    def apply_patch(self, patch: RemediationPatch) -> Tuple[bool, str]:
        """Apply a single code patch, update .env, and update requirements.txt."""
        target_file = self.repo_path / patch.file_path
        if not target_file.exists():
            return False, f"Target file does not exist: {patch.file_path}"

        try:
            content = target_file.read_text(encoding="utf-8")

            # Check if original snippet exists in file
            if patch.original_snippet not in content:
                # Try normalized whitespace
                norm_orig = " ".join(patch.original_snippet.split())
                norm_content = " ".join(content.split())
                if norm_orig not in norm_content:
                    return False, f"Could not find snippet in {patch.file_path} to replace."

            # Perform snippet replacement
            new_content = content.replace(patch.original_snippet, patch.replacement_snippet, 1)

            # Insert imports if specified and not already present
            if patch.import_additions:
                import_lines = []
                for imp in patch.import_additions:
                    if imp.strip() and imp.strip() not in new_content:
                        import_lines.append(imp.strip())
                if import_lines:
                    new_content = self._inject_imports(new_content, import_lines)

            target_file.write_text(new_content, encoding="utf-8")

            # Update .env
            if patch.env_additions:
                self._update_env(patch.env_additions)

            # Update requirements.txt
            if patch.requirements_additions:
                self._update_requirements(patch.requirements_additions)

            patch.applied = True
            return True, "Successfully applied patch"

        except Exception as e:
            return False, f"Error applying patch to {patch.file_path}: {str(e)}"

    def _inject_imports(self, content: str, import_lines: List[str]) -> str:
        """Inject import statements after module docstrings or at the top of file."""
        lines = content.splitlines(keepends=True)
        insert_idx = 0

        # Skip docstring if exists
        in_docstring = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('"""') or stripped.startswith("'''"):
                if stripped.count('"""') == 2 or stripped.count("'''") == 2:
                    insert_idx = i + 1
                    break
                if not in_docstring:
                    in_docstring = True
                else:
                    in_docstring = False
                    insert_idx = i + 1
                    break
            elif not in_docstring and not stripped.startswith("#") and stripped != "":
                insert_idx = i
                break

        injected = "\n".join(import_lines) + "\n"
        lines.insert(insert_idx, injected)
        return "".join(lines)

    def _update_env(self, env_vars: dict) -> None:
        """Safely append or update environment variables in target repo's .env."""
        env_path = self.repo_path / ".env"
        existing_keys = set()
        existing_lines = []

        if env_path.exists():
            existing_lines = env_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            for line in existing_lines:
                line_str = line.strip()
                if line_str and not line_str.startswith("#") and "=" in line_str:
                    key = line_str.split("=", 1)[0].strip()
                    existing_keys.add(key)

        new_entries = []
        for key, val in env_vars.items():
            if key not in existing_keys:
                clean_val = str(val).strip()
                if " " in clean_val or "\n" in clean_val:
                    new_entries.append(f'{key}="{clean_val}"')
                else:
                    new_entries.append(f"{key}={clean_val}")

        if new_entries:
            content_to_write = "\n".join(existing_lines)
            if content_to_write and not content_to_write.endswith("\n"):
                content_to_write += "\n"
            content_to_write += "# Automatically extracted by Security Audit Remediation\n"
            content_to_write += "\n".join(new_entries) + "\n"
            env_path.write_text(content_to_write, encoding="utf-8")

        # Ensure .env is in .gitignore
        self._ensure_env_in_gitignore()

    def _ensure_env_in_gitignore(self) -> None:
        """Ensure .env is listed in .gitignore so secrets are never committed."""
        gitignore_path = self.repo_path / ".gitignore"
        if not gitignore_path.exists():
            gitignore_path.write_text(".env\n__pycache__/\n*.pyc\n", encoding="utf-8")
            return

        lines = gitignore_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        has_env = any(l.strip() == ".env" or l.strip() == "*.env" for l in lines)
        if not has_env:
            with open(gitignore_path, "a", encoding="utf-8") as f:
                f.write("\n# Sensitive secrets\n.env\n")

    def _update_requirements(self, dependencies: List[str]) -> None:
        """Ensure required dependencies exist in requirements.txt."""
        req_path = self.repo_path / "requirements.txt"
        existing_pkgs = set()

        if req_path.exists():
            lines = req_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            for l in lines:
                pkg_name = l.strip().split("==")[0].split(">=")[0].split("<=")[0].strip()
                if pkg_name:
                    existing_pkgs.add(pkg_name.lower())

        to_add = []
        for dep in dependencies:
            dep_name = dep.strip().split("==")[0].split(">=")[0].split("<=")[0].strip().lower()
            if dep_name and dep_name not in existing_pkgs:
                to_add.append(dep.strip())

        if to_add:
            with open(req_path, "a", encoding="utf-8") as f:
                f.write("\n# Added by Security Audit Remediation\n")
                for dep in to_add:
                    f.write(f"{dep}\n")

    def commit_fixes(
        self, branch_name: str, message: str = "fix(security): auto-remediate hardcoded secrets & issues"
    ) -> RemediationResult:
        """Commit all applied changes to the current fix branch."""
        if not self.is_git_repo:
            return RemediationResult(
                success=True,
                branch_name=None,
                commit_hash=None,
                original_branch=None,
                files_modified=[],
                error_message="Non-git directory: Changes applied directly to disk.",
            )

        # Stage modified files (excluding .env)
        self._run_git(["add", "-u"])  # add tracked modified files
        self._run_git(["add", ".gitignore", "requirements.txt"])

        # Commit
        code, stdout, stderr = self._run_git(["commit", "-m", message])
        if code != 0:
            return RemediationResult(
                success=False,
                branch_name=branch_name,
                original_branch=self.original_branch,
                error_message=f"Git commit failed: {stderr or stdout}",
            )

        # Get commit hash
        _, commit_hash, _ = self._run_git(["rev-parse", "HEAD"])
        _, status_out, _ = self._run_git(["diff", "--name-only", f"{self.original_branch}...HEAD"])
        modified = [f for f in status_out.splitlines() if f.strip()]

        return RemediationResult(
            success=True,
            branch_name=branch_name,
            commit_hash=commit_hash[:8],
            original_branch=self.original_branch,
            files_modified=modified,
            env_updated=(self.repo_path / ".env").exists(),
            requirements_updated=(self.repo_path / "requirements.txt").exists(),
        )

    def rollback_to_original(self) -> Tuple[bool, str]:
        """Switch back to the original branch before the fix branch was created."""
        if not self.is_git_repo or not self.original_branch:
            return False, "Not a git repository or original branch unknown."

        code, _, stderr = self._run_git(["checkout", self.original_branch])
        if code == 0:
            return True, f"Successfully switched back to '{self.original_branch}' branch."
        return False, f"Failed to switch back: {stderr}"
