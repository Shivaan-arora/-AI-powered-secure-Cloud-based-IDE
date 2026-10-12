"""
Pydantic schemas for the /execute endpoint.
"""
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class SupportedLanguage(str, Enum):
    python = "python"
    cpp = "cpp"
    java = "java"


class ExecuteRequest(BaseModel):
    language: SupportedLanguage = Field(
        ..., description="Programming language to execute"
    )
    code: str = Field(
        ...,
        min_length=1,
        max_length=100_000,
        description="Source code to execute (max 100 KB)",
    )
    stdin: Optional[str] = Field(
        default="",
        max_length=10_000,
        description="Optional standard input to pass to the program",
    )

    @field_validator("code")
    @classmethod
    def strip_code(cls, v: str) -> str:
        return v.strip()


class SecuritySummary(BaseModel):
    risk: str = Field(..., description="LOW | MEDIUM | HIGH | CRITICAL")
    findings_count: int = 0
    ml_label: Optional[str] = None       # BENIGN | SUSPICIOUS | MALICIOUS
    ml_confidence: Optional[float] = None


class ExecuteResponse(BaseModel):
    status: str = Field(..., description="success | error | blocked | timeout")
    stdout: str = ""
    stderr: str = ""
    execution_time: float = 0.0          # seconds
    security: SecuritySummary
    container_id: Optional[str] = None  # sanitised (last 8 chars) for debugging
    message: Optional[str] = None
