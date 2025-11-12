from __future__ import annotations

import asyncio
import os
import uuid
from typing import Any, Dict, Optional

from celery import Celery

from app.core.config import get_settings
from app.services.scan_orchestrator import execute_scan

settings = get_settings()

celery_app = Celery("aws_securescope")
celery_app.conf.broker_url = settings.celery_config["broker_url"]
celery_app.conf.result_backend = settings.celery_config["result_backend"]
celery_app.conf.task_routes = {"app.services.tasks.run_scan_task": {"queue": "scans"}}
celery_app.conf.task_serializer = "json"
celery_app.conf.result_serializer = "json"
celery_app.conf.accept_content = ["json"]
celery_app.conf.worker_concurrency = int(os.getenv("CELERY_CONCURRENCY", "4"))


@celery_app.task(name="app.services.tasks.run_scan_task")
def run_scan_task(scan_id: str, credential_key: str, region_scope: Optional[list[str]]) -> None:
    asyncio.run(execute_scan(uuid.UUID(scan_id), credential_key, region_scope))


async def enqueue_scan(scan_id: uuid.UUID, credential_key: str, region_scope: Optional[list[str]]) -> None:
    run_scan_task.delay(str(scan_id), credential_key, region_scope)
