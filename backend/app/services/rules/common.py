from __future__ import annotations

from typing import Any, Dict, Iterable, List

from app.services.rules import utils


def bucket_encryption_rule(rule, resources: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for resource in resources:
        if resource.get("type") != "s3_bucket":
            continue
        if not resource.get("encryption_enabled", False):
            findings.append(
                utils.build_finding(
                    rule,
                    resource,
                    "FAIL",
                    {"message": "Bucket encryption not enforced"},
                )
            )
    return findings
