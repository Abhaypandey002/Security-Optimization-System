from __future__ import annotations

from typing import Any, Dict, Iterable, List

from app.services.rules import utils


def security_group_rule(rule, resources: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ports = rule.evaluation.get("ports", [])
    cidrs = rule.evaluation.get("cidrs", ["0.0.0.0/0", "::/0"])
    protocol = rule.evaluation.get("protocol", "tcp")
    statuses = rule.evaluation.get("status", "FAIL")
    findings: List[Dict[str, Any]] = []
    for resource in resources:
        if resource.get("type") != "security_group":
            continue
        exposures: List[Dict[str, Any]] = []
        for perm in resource.get("ip_permissions", []):
            perm_proto = perm.get("IpProtocol")
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            for rng in perm.get("IpRanges", []):
                cidr = rng.get("CidrIp")
                if cidr not in cidrs:
                    continue
                if perm_proto == "-1" or perm_proto == protocol or protocol == "*":
                    if not ports:
                        exposures.append({"protocol": perm_proto, "from_port": from_port, "to_port": to_port, "cidr": cidr})
                    elif from_port in ports or to_port in ports:
                        exposures.append({"protocol": perm_proto, "from_port": from_port, "to_port": to_port, "cidr": cidr})
        if exposures:
            findings.append(
                utils.build_finding(
                    rule,
                    resource,
                    statuses,
                    {
                        "exposures": exposures,
                        "security_group": resource.get("name"),
                        "description": resource.get("description"),
                    },
                )
            )
    return findings


def instance_metadata_rule(rule, resources: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for resource in resources:
        if resource.get("type") != "instance":
            continue
        metadata_options = resource.get("metadata_options", {})
        http_tokens = metadata_options.get("HttpTokens")
        if http_tokens != "required":
            findings.append(
                utils.build_finding(
                    rule,
                    resource,
                    "FAIL",
                    {
                        "http_tokens": http_tokens,
                        "public_ip": bool(resource.get("public_ip")),
                    },
                )
            )
    return findings


def instance_public_exposure(rule, resources: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for resource in resources:
        if resource.get("type") != "instance":
            continue
        public_ip = resource.get("public_ip")
        if not public_ip:
            continue
        metadata_options = resource.get("metadata_options", {})
        http_tokens = metadata_options.get("HttpTokens")
        security_groups = resource.get("security_groups", [])
        exposures = [sg for sg in security_groups if sg.get("GroupName")]
        if http_tokens != "required" or exposures:
            findings.append(
                utils.build_finding(
                    rule,
                    resource,
                    "CRITICAL",
                    {
                        "public_ip": public_ip,
                        "metadata_tokens": http_tokens,
                        "security_groups": [sg.get("GroupName") for sg in exposures],
                    },
                )
            )
    return findings


def volume_encryption_rule(rule, resources: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for resource in resources:
        if resource.get("type") != "ebs_volume":
            continue
        if not resource.get("encrypted"):
            findings.append(
                utils.build_finding(
                    rule,
                    resource,
                    "FAIL",
                    {
                        "attachments": [att.get("InstanceId") for att in resource.get("attachments", [])],
                        "kms_key_id": resource.get("kms_key_id"),
                    },
                )
            )
    return findings


def snapshot_sharing_rule(rule, resources: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for resource in resources:
        if resource.get("type") != "snapshot":
            continue
        shared_accounts = resource.get("shared_accounts", [])
        if shared_accounts:
            findings.append(
                utils.build_finding(
                    rule,
                    resource,
                    "WARN",
                    {"shared_accounts": shared_accounts},
                )
            )
    return findings


def instance_age_rule(rule, resources: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    threshold = rule.evaluation.get("ageDays", 180)
    findings: List[Dict[str, Any]] = []
    for resource in resources:
        if resource.get("type") != "instance":
            continue
        if resource.get("age_days") and resource["age_days"] > threshold:
            findings.append(
                utils.build_finding(
                    rule,
                    resource,
                    "WARN",
                    {"age_days": resource["age_days"], "threshold": threshold},
                )
            )
    return findings


def instance_profile_rule(rule, resources: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    wildcard_keywords = ["*", "AdministratorAccess"]
    for resource in resources:
        if resource.get("type") != "instance":
            continue
        profile = resource.get("iam_instance_profile") or {}
        arn = profile.get("Arn")
        if not arn:
            continue
        for keyword in wildcard_keywords:
            if keyword in arn:
                findings.append(
                    utils.build_finding(
                        rule,
                        resource,
                        "CRITICAL",
                        {"instance_profile": arn, "keyword": keyword},
                    )
                )
    return findings


def termination_protection_rule(rule, resources: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for resource in resources:
        if resource.get("type") != "instance":
            continue
        if not resource.get("termination_protection", False):
            findings.append(
                utils.build_finding(
                    rule,
                    resource,
                    "WARN",
                    {"termination_protection": False},
                )
            )
    return findings

