from datetime import datetime, timezone
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class Finding(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", validate_assignment=True)

    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: Literal["critical", "high", "medium", "low", "info"]
    asset: str = Field(min_length=1)
    description: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    impact: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    cvss: float | None = Field(default=None, ge=0, le=10, allow_inf_nan=False)
    status: Literal["open", "fixed", "accepted", "false_positive"] = "open"
    detected_by: str | None = None
    timestamp: AwareDatetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    references: list[str] = Field(default_factory=list)
    iso27001_controls: list[str] = Field(default_factory=list)
