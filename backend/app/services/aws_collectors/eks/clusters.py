from __future__ import annotations

import asyncio
from typing import List

from app.services.aws_collectors._boto import boto3
from app.services.aws_collectors.base import BaseCollector, CollectorResult


class EKSClusterCollector(BaseCollector):
    service = "EKS"

    async def collect(self) -> List[CollectorResult]:
        client = self.session.client("eks", region_name=self.region)
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, lambda: client.list_clusters())
        clusters = response.get("clusters", [])
        results: List[CollectorResult] = []
        for name in clusters:
            describe = await loop.run_in_executor(None, lambda: client.describe_cluster(name=name))
            cluster = describe.get("cluster", {})
            nodegroups = await loop.run_in_executor(None, lambda: client.list_nodegroups(clusterName=name))
            ng_details = []
            for nodegroup in nodegroups.get("nodegroups", []):
                detail = await loop.run_in_executor(None, lambda ng=nodegroup: client.describe_nodegroup(clusterName=name, nodegroupName=ng))
                ng = detail.get("nodegroup", {})
                ng_details.append(
                    {
                        "name": ng.get("nodegroupName"),
                        "version": ng.get("version"),
                        "ami_type": ng.get("amiType"),
                        "release_version": ng.get("releaseVersion"),
                        "status": ng.get("status"),
                    }
                )
            results.append(
                CollectorResult(
                    resource_id=cluster.get("arn", name),
                    configuration={
                        "id": cluster.get("arn", name),
                        "type": "eks_cluster",
                        "name": cluster.get("name"),
                        "region": self.region,
                        "version": cluster.get("version"),
                        "endpoint_public_access": cluster.get("resourcesVpcConfig", {}).get("endpointPublicAccess"),
                        "public_access_cidrs": cluster.get("resourcesVpcConfig", {}).get("publicAccessCidrs", []),
                        "logging": cluster.get("logging", {}),
                        "tags": cluster.get("tags", {}),
                        "nodegroups": ng_details,
                    },
                )
            )
        return results
