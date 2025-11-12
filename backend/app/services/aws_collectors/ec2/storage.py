from __future__ import annotations

import asyncio
from typing import List

from app.services.aws_collectors._boto import boto3
from app.services.aws_collectors.base import BaseCollector, CollectorResult


class EBSVolumeCollector(BaseCollector):
    service = "EC2"

    async def collect(self) -> List[CollectorResult]:
        client = self.session.client("ec2", region_name=self.region)
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, lambda: client.describe_volumes())
        results: List[CollectorResult] = []
        for volume in response.get("Volumes", []):
            results.append(
                CollectorResult(
                    resource_id=volume["VolumeId"],
                    configuration={
                        "id": volume["VolumeId"],
                        "type": "ebs_volume",
                        "encrypted": volume.get("Encrypted"),
                        "region": self.region,
                        "attachments": volume.get("Attachments", []),
                        "kms_key_id": volume.get("KmsKeyId"),
                        "multi_attach": volume.get("MultiAttachEnabled"),
                    },
                )
            )
        return results


class SnapshotCollector(BaseCollector):
    service = "EC2"

    async def collect(self) -> List[CollectorResult]:
        client = self.session.client("ec2", region_name=self.region)
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: client.describe_snapshots(OwnerIds=["self"]),
        )
        results: List[CollectorResult] = []
        for snapshot in response.get("Snapshots", []):
            results.append(
                CollectorResult(
                    resource_id=snapshot["SnapshotId"],
                    configuration={
                        "id": snapshot["SnapshotId"],
                        "type": "snapshot",
                        "encrypted": snapshot.get("Encrypted"),
                        "region": self.region,
                        "kms_key_id": snapshot.get("KmsKeyId"),
                        "shared_accounts": snapshot.get("SharedAccounts", []),
                    },
                )
            )
        return results
