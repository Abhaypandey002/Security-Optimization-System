from __future__ import annotations

import hashlib
from typing import Any, Dict


def anonymize_identifier(identifier: str) -> str:
    return hashlib.sha256(identifier.encode()).hexdigest()


def build_finding(rule, resource: Dict[str, Any], status: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "rule_id": rule.id,
        "service": rule.service,
        "severity": rule.severity,
        "status": status,
        "resource_hash": anonymize_identifier(resource.get("id", "unknown")),
        "evidence": evidence,
        "region": resource.get("region"),
    }
