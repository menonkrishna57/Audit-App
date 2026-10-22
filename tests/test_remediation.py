"""
Verification test for 2-Tier Remediation Pipeline, Secret Extraction, and Git Isolation.
"""
import os
import sys
import shutil
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from remediation import AuditorAgent, FixerSubagent, GitManager, Finding

def test_secret_detection_and_remediation():
    temp_dir = Path("f:/Audit-App/.test_tmp")
    if temp_dir.exists():
        shutil.rmtree(temp_dir, ignore_errors=True)
    temp_dir.mkdir(parents=True, exist_ok=True)
    try:
        sample_file = temp_dir / "service_client.py"
        sample_file.write_text("""# Payment and AI service client
import sys

def connect_service():
    api_key = "AIzaSyA_DEMO_TEST_KEY_1234567890123456789"
    print("Connecting with key:", api_key)
    return True

if __name__ == "__main__":
    connect_service()
""", encoding="utf-8")

        req_file = temp_dir / "requirements.txt"
        req_file.write_text("requests==2.31.0\n", encoding="utf-8")

        print(f"Created test repository at: {temp_dir}")

        git = GitManager(str(temp_dir))
        git.init_git_repo_if_needed()
        original_branch = git.get_current_branch()
        print(f"Initial Git branch: {original_branch}")

        auditor = AuditorAgent()
        findings = auditor.scan_file_for_secrets(sample_file, temp_dir)
        print(f"AuditorAgent detected {len(findings)} findings.")
        assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
        finding = findings[0]
        assert finding.issue_type == "HARDCODED_SECRET"

        fixer = FixerSubagent()
        patch = fixer.generate_patch(finding, temp_dir)
        assert patch is not None, "FixerSubagent failed to generate patch"

        fix_branch = git.create_fix_branch("audit-fixes-test")
        print(f"Created and switched to isolation branch: {fix_branch}")

        ok, msg = git.apply_patch(patch)
        assert ok, f"apply_patch failed: {msg}"

        commit_res = git.commit_fixes(fix_branch, "test: apply security remediations")
        assert commit_res.success, f"Commit failed: {commit_res.error_message}"

        updated_content = sample_file.read_text(encoding="utf-8")
        assert "os.getenv" in updated_content
        assert "load_dotenv" in updated_content

        env_content = (temp_dir / ".env").read_text(encoding="utf-8")
        assert "AIzaSyA_DEMO_TEST_KEY_1234567890123456789" in env_content

        req_content = req_file.read_text(encoding="utf-8")
        assert "python-dotenv" in req_content

        gitignore_content = (temp_dir / ".gitignore").read_text(encoding="utf-8")
        assert ".env" in gitignore_content

        rollback_ok, rollback_msg = git.rollback_to_original()
        assert rollback_ok

        print("\nALL VERIFICATION CHECKS PASSED SUCCESSFULLY!")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    test_secret_detection_and_remediation()
