from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator


class CredentialBundle(BaseModel):
    access_key_id: str = Field(..., alias="accessKeyId")
    secret_access_key: str = Field(..., alias="secretAccessKey")
    region_scope: Optional[List[str]] = Field(None, alias="regionScope")
    role_arn: Optional[str] = Field(None, alias="roleArn")
    external_id: Optional[str] = Field(None, alias="externalId")

    class Config:
        allow_population_by_field_name = True
        anystr_strip_whitespace = True
        min_anystr_length = 1

    @validator("region_scope", pre=True)
    def validate_region_scope(cls, value):
        if value in (None, "all"):
            return None
        if isinstance(value, str):
            return [value]
        return value


class ScanRequest(CredentialBundle):
    pass


class RegionProgress(BaseModel):
    region: str
    status: str
    service_progress: Dict[str, str] = Field(default_factory=dict)


class ScanStatusResponse(BaseModel):
    scan_id: uuid.UUID
    status: str
    regions: List[RegionProgress]


class FindingExport(BaseModel):
    rule_id: str
    service: str
    severity: str
    status: str
    region: Optional[str]
    evidence: Dict[str, Any]


class ScanExport(BaseModel):
    scan_id: uuid.UUID
    summary: Dict[str, Any]
    findings: List[FindingExport]
