from __future__ import annotations

from app.services.policy_engine import PolicyEngine
from app.services.rules import eks


def test_endpoint_restriction_rule_flags_public_endpoint():
    rule = next(r for r in PolicyEngine().load_rules("eks") if r.id == "EKS_PUBLIC_ENDPOINT_NO_CIDR")
    resources = [
        {
            "id": "arn:aws:eks:us-west-2:123:cluster/demo",
            "type": "eks_cluster",
            "region": "us-west-2",
            "endpoint_public_access": True,
            "public_access_cidrs": [],
        }
    ]
    findings = eks.endpoint_restriction_rule(rule, resources)
    assert findings
    assert findings[0]["severity"] == "HIGH"


def test_control_plane_logging_rule_missing_logs():
    rule = next(r for r in PolicyEngine().load_rules("eks") if r.id == "EKS_CONTROL_PLANE_LOGGING")
    resources = [
        {
            "id": "arn:aws:eks:us-west-2:123:cluster/demo",
            "type": "eks_cluster",
            "region": "us-west-2",
            "logging": {"clusterLogging": [{"enabled": False, "types": ["api"]}]},
        }
    ]
    findings = eks.control_plane_logging_rule(rule, resources)
    assert findings
    assert "api" in findings[0]["evidence"]["missing_logs"]


def test_version_skew_rule_nodegroup():
    rule = next(r for r in PolicyEngine().load_rules("eks") if r.id == "EKS_VERSION_DRIFT_NODEGROUP")
    resources = [
        {
            "id": "arn:aws:eks:us-west-2:123:cluster/demo",
            "type": "eks_cluster",
            "region": "us-west-2",
            "version": "1.26",
            "nodegroups": [
                {"name": "ng1", "version": "1.24"},
            ],
        }
    ]
    findings = eks.version_skew_rule(rule, resources)
    assert findings
    nodegroup_finding = next(f for f in findings if "nodegroup" in f["evidence"])
    assert nodegroup_finding["evidence"]["nodegroup"] == "ng1"
