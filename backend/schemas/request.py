from pydantic import BaseModel, Field, field_validator
from typing import Optional


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=100_000, description="Normalized text to analyze")
    hash: str = Field(..., min_length=64, max_length=64, description="SHA-256 of original input")

    @field_validator("text")
    @classmethod
    def strip_null_bytes(cls, v: str) -> str:
        """Strip null bytes and control chars from input."""
        return v.replace("\x00", "").replace("\r", "").strip()

    @field_validator("hash")
    @classmethod
    def validate_hex(cls, v: str) -> str:
        if not all(c in "0123456789abcdef" for c in v.lower()):
            raise ValueError("hash must be lowercase hex")
        return v.lower()


class AIAnalysisResult(BaseModel):
    promptInjectionScore: float = Field(..., ge=0.0, le=1.0)
    obfuscationScore: float = Field(..., ge=0.0, le=1.0)
    malwareSignatureMatches: list[str]
    threatSummary: str
    modelUsed: str
    latencyMs: int
