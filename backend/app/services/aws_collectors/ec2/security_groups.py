from __future__ import annotations

import asyncio
from typing import List

from app.services.aws_collectors._boto import boto3
from app.services.aws_collectors.base import BaseCollector, CollectorResult


class SecurityGroupCollector(BaseCollector):
    service = "EC2"

    async def collect(self) -> List[CollectorResult]:
        client = self.session.client("ec2", region_name=self.region)
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, lambda: client.describe_security_groups())
        results: List[CollectorResult] = []
        for sg in response.get("SecurityGroups", []):
            results.append(
                CollectorResult(
                    resource_id=sg["GroupId"],
                    configuration={
                        "id": sg["GroupId"],
                        "type": "security_group",
                        "name": sg.get("GroupName"),
                        "description": sg.get("Description"),
                        "region": self.region,
                        "ip_permissions": sg.get("IpPermissions", []),
                        "ip_permissions_egress": sg.get("IpPermissionsEgress", []),
                    },
                )
            )
        return results
