from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List

from app.services.aws_collectors._boto import boto3


@dataclass
class CollectorResult:
    resource_id: str
    configuration: Dict[str, Any]


class BaseCollector:
    service: str

    def __init__(self, session: boto3.Session, region: str) -> None:
        self.session = session
        self.region = region

    async def collect(self) -> List[CollectorResult]:
        raise NotImplementedError

    async def _paginate(self, func, result_key: str, **kwargs) -> Iterable[Dict[str, Any]]:
        client = func.__self__  # type: ignore[attr-defined]
        paginator = client.get_paginator(func.__name__)
        loop = asyncio.get_event_loop()
        pages = await loop.run_in_executor(None, lambda: paginator.paginate(**kwargs))
        for page in pages:
            for item in page.get(result_key, []):
                yield item
