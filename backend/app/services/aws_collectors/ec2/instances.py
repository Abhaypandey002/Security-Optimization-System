from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import List

from app.services.aws_collectors._boto import boto3
from app.services.aws_collectors.base import BaseCollector, CollectorResult


class InstanceCollector(BaseCollector):
    service = "EC2"

    async def collect(self) -> List[CollectorResult]:
        client = self.session.client("ec2", region_name=self.region)
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, lambda: client.describe_instances())
        results: List[CollectorResult] = []
        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_id = instance["InstanceId"]
                metadata_options = instance.get("MetadataOptions", {})
                block_devices = instance.get("BlockDeviceMappings", [])
                launch_time = instance.get("LaunchTime")
                age_days = None
                if isinstance(launch_time, datetime):
                    age_days = (datetime.now(timezone.utc) - launch_time).days
                disable_api_termination = await loop.run_in_executor(
                    None,
                    lambda: client.describe_instance_attribute(
                        InstanceId=instance_id, Attribute="disableApiTermination"
                    ),
                )
                termination_protection = (
                    disable_api_termination
                    .get("DisableApiTermination", {})
                    .get("Value", False)
                )
                results.append(
                    CollectorResult(
                        resource_id=instance_id,
                        configuration={
                            "id": instance_id,
                            "type": "instance",
                            "region": self.region,
                            "state": instance.get("State", {}).get("Name"),
                            "public_ip": instance.get("PublicIpAddress"),
                            "security_groups": instance.get("SecurityGroups", []),
                            "iam_instance_profile": instance.get("IamInstanceProfile"),
                            "metadata_options": metadata_options,
                            "root_device_type": instance.get("RootDeviceType"),
                            "block_device_mappings": block_devices,
                            "launch_time": launch_time.isoformat() if isinstance(launch_time, datetime) else None,
                            "age_days": age_days,
                            "ebs_optimized": instance.get("EbsOptimized"),
                            "platform_details": instance.get("PlatformDetails"),
                            "termination_protection": termination_protection,
                        },
                    )
                )
        return results
