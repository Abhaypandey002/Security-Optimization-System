from __future__ import annotations

from typing import Any, Dict, Iterable, List

from packaging import version

from app.services.rules import utils


SUPPORTED_MINOR_DRIFT = 1


def endpoint_restriction_rule(rule, resources: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for resource in resources:
        if resource.get("type") != "eks_cluster":
            continue
        if resource.get("endpoint_public_access") and not resource.get("public_access_cidrs"):
            findings.append(
                utils.build_finding(
                    rule,
                    resource,
                    "HIGH",
                    {
                        "public_access": True,
                        "cidrs": resource.get("public_access_cidrs", []),
                    },
                )
            )
    return findings


def control_plane_logging_rule(rule, resources: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    required = set(rule.evaluation.get("requiredLogs", ["api", "audit", "authenticator"]))
    findings: List[Dict[str, Any]] = []
    for resource in resources:
        if resource.get("type") != "eks_cluster":
            continue
        enabled_types = set()
        for log in resource.get("logging", {}).get("clusterLogging", []):
            if log.get("enabled"):
                enabled_types.update(log.get("types", []))
        missing = required - enabled_types
        if missing:
            findings.append(
                utils.build_finding(
                    rule,
                    resource,
                    "HIGH",
                    {"missing_logs": sorted(missing)},
                )
            )
    return findings


def version_skew_rule(rule, resources: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    current_version = version.parse(rule.evaluation.get("currentVersion", "1.29"))
    drift = int(rule.evaluation.get("minorDrift", SUPPORTED_MINOR_DRIFT))
    findings: List[Dict[str, Any]] = []
    for resource in resources:
        if resource.get("type") != "eks_cluster":
            continue
        cluster_version = resource.get("version")
        if not cluster_version:
            continue
        cluster_ver = version.parse(cluster_version)
        if current_version.major != cluster_ver.major:
            findings.append(
                utils.build_finding(
                    rule,
                    resource,
                    "HIGH",
                    {"cluster_version": cluster_version, "current_version": str(current_version)},
                )
            )
            continue
        if current_version.minor - cluster_ver.minor > drift:
            findings.append(
                utils.build_finding(
                    rule,
                    resource,
                    "WARN",
                    {"cluster_version": cluster_version, "current_version": str(current_version)},
                )
            )
        for nodegroup in resource.get("nodegroups", []):
            node_ver = nodegroup.get("version")
            if not node_ver:
                continue
            node_parsed = version.parse(node_ver)
            if cluster_ver.minor - node_parsed.minor > drift:
                findings.append(
                    utils.build_finding(
                        rule,
                        {"id": f"{resource['id']}::{nodegroup['name']}", "region": resource.get("region")},
                        "WARN",
                        {
                            "cluster_version": cluster_version,
                            "nodegroup_version": node_ver,
                            "nodegroup": nodegroup.get("name"),
                        },
                    )
                )
    return findings


def irsa_usage_rule(rule, resources: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for resource in resources:
        if resource.get("type") != "eks_cluster":
            continue
        tags = resource.get("tags", {})
        if not any(tag.startswith("iamserviceaccount") for tag in tags.keys()):
            findings.append(
                utils.build_finding(
                    rule,
                    resource,
                    "WARN",
                    {"message": "No IRSA tags detected"},
                )
            )
    return findings
