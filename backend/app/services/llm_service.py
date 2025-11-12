from __future__ import annotations

import asyncio
import hashlib
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.llm.providers.mistral_local import LocalMistralProvider
from app.models.scan import Finding, LLMAdvice


class LLMService:
    def __init__(self, db: Session) -> None:
        self.db = db
        try:
            self.provider = LocalMistralProvider()
        except Exception:
            self.provider = None

    async def enrich_findings(self, findings: List[Finding]) -> None:
        if not findings or not self.provider:
            return
        payload = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "evidence": {k: v for k, v in f.evidence.items() if k != "resource_id"},
            }
            for f in findings
        ]
        prompt_hash = hashlib.sha256(str(payload).encode()).hexdigest()
        advice_md = await self.provider.generate(payload)
        for finding in findings:
            self.db.add(
                LLMAdvice(
                    finding_id=finding.id,
                    model="mistral-7b-instruct",
                    prompt_hash=prompt_hash,
                    content_md=advice_md,
                )
            )
        self.db.commit()
