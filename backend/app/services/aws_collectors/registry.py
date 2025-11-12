from __future__ import annotations

from typing import List

from app.services.aws_collectors._boto import boto3

from app.services.aws_collectors.base import BaseCollector
from app.services.aws_collectors.ec2.security_groups import SecurityGroupCollector
from app.services.aws_collectors.ec2.instances import InstanceCollector
from app.services.aws_collectors.ec2.storage import EBSVolumeCollector, SnapshotCollector
from app.services.aws_collectors.eks.clusters import EKSClusterCollector
from app.services.aws_collectors.common.global_services import GlobalServiceCollector


class CollectorRegistry:
    def __init__(self, session: boto3.Session) -> None:
        self.session = session

    def get_collectors(self, region: str) -> List[BaseCollector]:
        collectors: List[BaseCollector] = [
            SecurityGroupCollector(self.session, region),
            InstanceCollector(self.session, region),
            EBSVolumeCollector(self.session, region),
            SnapshotCollector(self.session, region),
            EKSClusterCollector(self.session, region),
        ]
        if region.upper() == "GLOBAL":
            collectors.append(GlobalServiceCollector(self.session, region))
        return collectors
