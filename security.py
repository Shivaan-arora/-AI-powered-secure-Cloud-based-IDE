"""
Pydantic schemas for the /security/scan endpoint.
"""
from typing import List, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    code: str = Field(
        ...,
        min_length=1,
        max_length=100_000,
        description="Source code to analyse",
    )
    language: str = Field(default="python", description="Language hint")


class Finding(BaseModel):
    type: str          # dangerous_function | network | file_access | dynamic_import …
    name: str          # The offending symbol / pattern
    severity: str      # LOW | MEDIUM | HIGH | CRITICAL
    line: Optional[int] = None
    message: str


class ScanResponse(BaseModel):
    risk: str          # LOW | MEDIUM | HIGH | CRITICAL
    findings: List[Finding] = []
    summary: str = ""
    scan_time: float = 0.0   # seconds
