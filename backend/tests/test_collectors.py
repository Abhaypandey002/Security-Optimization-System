from __future__ import annotations

import asyncio

from app.services.aws_collectors.ec2.security_groups import SecurityGroupCollector


class FakeEC2Client:
    def describe_security_groups(self):
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-123",
                    "GroupName": "default",
                    "Description": "default group",
                    "IpPermissions": [],
                    "IpPermissionsEgress": [],
                }
            ]
        }


class FakeSession:
    def client(self, service_name, region_name=None):
        assert service_name == "ec2"
        return FakeEC2Client()


def test_security_group_collector_returns_results():
    collector = SecurityGroupCollector(FakeSession(), "us-east-1")
    results = asyncio.run(collector.collect())
    assert len(results) == 1
    assert results[0].configuration["id"] == "sg-123"
