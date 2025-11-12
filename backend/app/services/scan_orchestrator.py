from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

import boto3
from botocore.exceptions import ClientError
from sqlalchemy.orm import Session

from app.core import credentials
from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models.scan import Finding, LLMAdvice, RuleCatalog, ScanRegion, ScanRun, ScanStatusEnum
from app.services import schemas
from app.services.aws_collectors.registry import CollectorRegistry
from app.services.policy_engine import PolicyEngine
from app.services.tasks import enqueue_scan
from app.services.llm_service import LLMService

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    def __init__(self, db: Optional[Session] = None) -> None:
        self.db = db
        self.settings = get_settings()
        self.rule_engine = PolicyEngine()

    async def start_scan(self, request: schemas.ScanRequest) -> uuid.UUID:
        caller_identity, minimal_permissions = await asyncio.to_thread(self._validate_credentials, request)

        scan_id = uuid.uuid4()
        if not self.db:
            raise RuntimeError("Database session required to start a scan")

        scan_run = ScanRun(
            id=scan_id,
            status=ScanStatusEnum.pending.value,
            region_scope=request.region_scope or ["all"],
            caller_identity=caller_identity,
            minimal_permissions=minimal_permissions,
        )
        self.db.add(scan_run)
        regions = request.region_scope or ["all"]
        if regions == ["all"]:
            regions = ["GLOBAL"]
        for region in regions:
            self.db.add(
                ScanRegion(
                    id=uuid.uuid4(),
                    scan_id=scan_id,
                    region=region,
                    status=ScanStatusEnum.pending.value,
                )
            )
        self.db.commit()

        cred_key = credentials.vault.store(
            credentials.EphemeralCredential(
                access_key_id=request.access_key_id,
                secret_access_key=request.secret_access_key,
                role_arn=request.role_arn,
                external_id=request.external_id,
            )
        )

        await enqueue_scan(scan_id=scan_id, credential_key=cred_key, region_scope=request.region_scope)
        return scan_id

    async def get_status(self, scan_id: uuid.UUID) -> schemas.ScanStatusResponse:
        if not self.db:
            raise RuntimeError("Database session required")
        scan = self.db.get(ScanRun, scan_id)
        if not scan:
            raise ValueError("Scan not found")
        regions = [
            schemas.RegionProgress(region=r.region, status=r.status, service_progress={})
            for r in scan.regions
        ]
        return schemas.ScanStatusResponse(scan_id=scan.id, status=scan.status, regions=regions)

    async def get_summary(self, scan_id: uuid.UUID) -> Dict[str, Any]:
        if not self.db:
            raise RuntimeError("Database session required")
        scan = self.db.get(ScanRun, scan_id)
        if not scan:
            raise ValueError("Scan not found")
        findings = self.db.query(Finding).filter(Finding.scan_id == scan_id).all()
        severities: Dict[str, int] = defaultdict(int)
        services: Dict[str, int] = defaultdict(int)
        for finding in findings:
            severities[finding.severity] += 1
            services[finding.service] += 1
        return {
            "scanId": str(scan.id),
            "status": scan.status,
            "severityTotals": dict(severities),
            "serviceTotals": dict(services),
            "totalFindings": len(findings),
        }

    async def export_scan(self, scan_id: uuid.UUID, format: str = "json") -> Any:
        if not self.db:
            raise RuntimeError("Database session required")
        scan: ScanRun = self.db.query(ScanRun).get(scan_id)
        if not scan:
            raise ValueError("Scan not found")
        findings = self.db.query(Finding).filter(Finding.scan_id == scan_id).all()
        export = schemas.ScanExport(
            scan_id=scan.id,
            summary=await self.get_summary(scan_id),
            findings=[
                schemas.FindingExport(
                    rule_id=f.rule_id,
                    service=f.service,
                    severity=f.severity,
                    status=f.status,
                    region=f.region,
                    evidence=f.evidence,
                )
                for f in findings
            ],
        )
        if format == "json":
            return json.loads(export.json())
        if format == "md":
            lines = [f"# Scan {scan.id}", "## Summary"]
            summary = export.summary
            lines.append(f"Status: {summary['status']}")
            lines.append(f"Total Findings: {summary['totalFindings']}")
            lines.append("## Findings")
            for item in export.findings:
                lines.append(f"### {item.rule_id} ({item.service})")
                lines.append(f"Severity: {item.severity}")
                lines.append(f"Region: {item.region or 'global'}")
                lines.append("Evidence:")
                lines.append(f"````json\n{json.dumps(item.evidence, indent=2)}\n````")
            return "\n\n".join(lines)
        raise ValueError("Unsupported format")

    def _validate_credentials(self, request: schemas.ScanRequest) -> tuple[Dict[str, Any], Dict[str, Any]]:
        session = boto3.Session(
            aws_access_key_id=request.access_key_id,
            aws_secret_access_key=request.secret_access_key,
        )
        client = session.client("sts")
        try:
            identity = client.get_caller_identity()
        except ClientError as exc:
            logger.error("Credential validation failed: %s", exc, exc_info=False)
            raise
        minimal_permissions = {"sts:GetCallerIdentity": True}
        probe_calls = {
            "ec2:DescribeSecurityGroups": ("ec2", "describe_security_groups", {"MaxResults": 5}, "us-east-1"),
            "eks:ListClusters": ("eks", "list_clusters", {}, "us-east-1"),
            "s3:ListAllMyBuckets": ("s3", "list_buckets", {}, None),
        }
        for action, (service, method, kwargs, region) in probe_calls.items():
            try:
                probe_client = session.client(service, region_name=region)
                getattr(probe_client, method)(**kwargs)
                minimal_permissions[action] = True
            except ClientError:
                minimal_permissions[action] = False
        return identity, minimal_permissions


async def execute_scan(scan_id: uuid.UUID, credential_key: str, region_scope: Optional[List[str]]) -> None:
    cred = credentials.vault.retrieve(credential_key)
    if not cred:
        logger.error("Credentials expired before scan execution")
        return

    session = boto3.Session(
        aws_access_key_id=cred.access_key_id,
        aws_secret_access_key=cred.secret_access_key,
    )

    collector_registry = CollectorRegistry(session=session)
    rule_engine = PolicyEngine()

    # Determine regions
    if region_scope:
        regions = list(region_scope)
        if "GLOBAL" not in [r.upper() for r in regions]:
            regions.append("GLOBAL")
    else:
        ec2 = session.client("ec2", region_name="us-east-1")
        response = ec2.describe_regions(AllRegions=True)
        regions = [r["RegionName"] for r in response["Regions"] if r.get("OptInStatus") in ("opt-in-not-required", "opted-in")]
        regions.append("GLOBAL")

    await asyncio.gather(
        *[
            _run_region_scan(scan_id, session, region, collector_registry, rule_engine)
            for region in regions
        ]
    )
    credentials.vault.revoke(credential_key)


async def _run_region_scan(
    scan_id: uuid.UUID,
    session: boto3.Session,
    region: str,
    registry: CollectorRegistry,
    rule_engine: PolicyEngine,
) -> None:
    db = SessionLocal()
    scan_region = None
    try:
        scan_run = db.get(ScanRun, scan_id)
        if not scan_run:
            return
        scan_run.status = ScanStatusEnum.running.value
        scan_region = (
            db.query(ScanRegion)
            .filter(ScanRegion.scan_id == scan_id, ScanRegion.region == region)
            .first()
        )
        if not scan_region:
            scan_region = ScanRegion(
                id=uuid.uuid4(),
                scan_id=scan_id,
                region=region,
                status=ScanStatusEnum.pending.value,
            )
            db.add(scan_region)
            db.flush()
        if scan_region:
            scan_region.status = ScanStatusEnum.running.value
            scan_region.started_at = datetime.utcnow()
        collectors = registry.get_collectors(region)
        llm_candidates: List[Finding] = []
        for collector in collectors:
            resources = [r.configuration for r in await collector.collect()]
            findings = rule_engine.evaluate(collector.service, resources)
            for finding in findings:
                finding_model = Finding(
                    id=uuid.uuid4(),
                    scan_id=scan_id,
                    service=finding["service"],
                    rule_id=finding["rule_id"],
                    severity=finding["severity"],
                    status=finding["status"],
                    evidence=finding["evidence"],
                    region=finding.get("region", region),
                    resource_hash=finding.get("resource_hash"),
                )
                db.add(finding_model)
                llm_candidates.append(finding_model)
        if scan_region:
            scan_region.status = ScanStatusEnum.completed.value
            scan_region.finished_at = datetime.utcnow()
        db.commit()
        if llm_candidates:
            service = LLMService(db)
            await service.enrich_findings(llm_candidates)
        remaining = (
            db.query(ScanRegion)
            .filter(ScanRegion.scan_id == scan_id, ScanRegion.status != ScanStatusEnum.completed.value)
            .count()
        )
        if remaining == 0:
            scan_run.status = ScanStatusEnum.completed.value
        db.commit()
    except Exception:
        db.rollback()
        if scan_region:
            scan_region.status = ScanStatusEnum.failed.value
            scan_region.finished_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()
