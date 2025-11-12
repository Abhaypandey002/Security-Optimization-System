from __future__ import annotations

import asyncio
from typing import List

from app.services.aws_collectors._boto import boto3
from app.services.aws_collectors.base import BaseCollector, CollectorResult


class GlobalServiceCollector(BaseCollector):
    service = "COMMON"

    async def collect(self) -> List[CollectorResult]:
        region = None if self.region.upper() == "GLOBAL" else self.region
        s3_client = self.session.client("s3", region_name=region)
        loop = asyncio.get_event_loop()
        buckets_resp = await loop.run_in_executor(None, s3_client.list_buckets)
        buckets = buckets_resp.get("Buckets", [])
        results: List[CollectorResult] = []
        for bucket in buckets:
            name = bucket["Name"]
            location = await loop.run_in_executor(None, lambda: s3_client.get_bucket_location(Bucket=name))
            region = location.get("LocationConstraint") or "us-east-1"
            try:
                encryption = await loop.run_in_executor(None, lambda: s3_client.get_bucket_encryption(Bucket=name))
                rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                encryption_enabled = bool(rules)
            except Exception:
                encryption_enabled = False
            results.append(
                CollectorResult(
                    resource_id=name,
                    configuration={
                        "id": name,
                        "type": "s3_bucket",
                        "region": region,
                        "encryption_enabled": encryption_enabled,
                    },
                )
            )
        return results
