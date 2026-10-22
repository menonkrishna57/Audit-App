from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class Finding(BaseModel):
    """Represents a discrete vulnerability or issue discovered in the codebase."""
    id: str = Field(description="Unique finding identifier, e.g., SEC-001")
    file_path: str = Field(description="Path to the file relative to repository root")
    issue_type: str = Field(
        description="Type of issue: HARDCODED_SECRET, SQL_INJECTION, INSECURE_CONFIG, etc."
    )
    severity: str = Field(
        description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, or INFO"
    )
    description: str = Field(description="Clear explanation of the detected problem")
    code_snippet: str = Field(
        description="The original vulnerable code snippet from the file"
    )
    line_number: Optional[int] = Field(
        default=None, description="Estimated line number if identifiable"
    )
    recommendation: Optional[str] = Field(
        default=None, description="Remediation guidance"
    )


class RemediationPatch(BaseModel):
    """Represents a concrete, atomic code and configuration patch to fix a finding."""
    finding_id: str = Field(description="ID of the finding being resolved")
    file_path: str = Field(description="Target file path to modify")
    original_snippet: str = Field(
        description="The exact text chunk in the original file to be replaced"
    )
    replacement_snippet: str = Field(
        description="The exact replacement text to substitute"
    )
    unified_diff: str = Field(
        description="Unified diff format of the change for preview in UI"
    )
    env_additions: Dict[str, str] = Field(
        default_factory=dict,
        description="Key-value pairs to add into the repository's .env file"
    )
    requirements_additions: List[str] = Field(
        default_factory=list,
        description="Packages to append to requirements.txt (e.g. python-dotenv>=1.0.0)"
    )
    import_additions: List[str] = Field(
        default_factory=list,
        description="Any imports that must be added at the top of the file"
    )
    explanation: str = Field(
        default="", description="Detailed rationale of why this patch resolves the issue"
    )
    applied: bool = Field(
        default=False, description="Whether this patch has been committed to disk"
    )


class RemediationResult(BaseModel):
    """The result of applying one or more remediation patches to disk and Git."""
    success: bool
    branch_name: Optional[str] = None
    commit_hash: Optional[str] = None
    original_branch: Optional[str] = None
    files_modified: List[str] = Field(default_factory=list)
    env_updated: bool = False
    requirements_updated: bool = False
    error_message: Optional[str] = None


class AuditReport(BaseModel):
    """Complete audit and remediation report containing findings and generated patches."""
    timestamp: str
    target_path: str
    summary: str
    findings: List[Finding] = Field(default_factory=list)
    patches: List[RemediationPatch] = Field(default_factory=list)
    category_reports: Dict[str, Any] = Field(default_factory=dict)
