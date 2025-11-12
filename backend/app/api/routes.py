from __future__ import annotations

import uuid
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_db
from app.models.scan import Finding, LLMAdvice, ScanRegion, ScanRun
from app.services.scan_orchestrator import ScanOrchestrator
from app.services.schemas import ScanRequest, ScanStatusResponse

settings = get_settings()

api_router = APIRouter()


@api_router.post("/scans/start", response_model=dict)
async def start_scan(scan_request: ScanRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    orchestrator = ScanOrchestrator(db=db)
    scan_id = await orchestrator.start_scan(scan_request)
    return {"scanId": str(scan_id)}


@api_router.get("/scans/{scan_id}/status", response_model=ScanStatusResponse)
async def scan_status(scan_id: uuid.UUID, db: Session = Depends(get_db)) -> ScanStatusResponse:
    orchestrator = ScanOrchestrator(db=db)
    return await orchestrator.get_status(scan_id)


@api_router.get("/scans/{scan_id}/summary")
async def scan_summary(scan_id: uuid.UUID, db: Session = Depends(get_db)) -> dict[str, Any]:
    orchestrator = ScanOrchestrator(db=db)
    return await orchestrator.get_summary(scan_id)


@api_router.get("/scans/{scan_id}/findings")
async def list_findings(
    scan_id: uuid.UUID,
    service: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = db.query(Finding).filter(Finding.scan_id == scan_id)
    if service:
        query = query.filter(Finding.service == service)
    if severity:
        query = query.filter(Finding.severity == severity)
    findings = query.all()
    return {
        "items": [
            {
                "id": str(f.id),
                "ruleId": f.rule_id,
                "service": f.service,
                "severity": f.severity,
                "status": f.status,
                "evidence": f.evidence,
                "region": f.region,
            }
            for f in findings
        ]
    }


@api_router.get("/scans/{scan_id}/export.json")
async def export_scan_json(scan_id: uuid.UUID, db: Session = Depends(get_db)) -> JSONResponse:
    orchestrator = ScanOrchestrator(db=db)
    export = await orchestrator.export_scan(scan_id, format="json")
    return JSONResponse(content=export)


@api_router.get("/scans/{scan_id}/export.md")
async def export_scan_md(scan_id: uuid.UUID, db: Session = Depends(get_db)) -> JSONResponse:
    orchestrator = ScanOrchestrator(db=db)
    export = await orchestrator.export_scan(scan_id, format="md")
    return JSONResponse(content={"content": export})


@api_router.get("/catalog/rules")
async def list_rules(service: Optional[str] = Query(None)) -> dict[str, Any]:
    orchestrator = ScanOrchestrator()
    rules = orchestrator.rule_engine.load_rules(service)
    return {"items": [rule.dict() for rule in rules]}
