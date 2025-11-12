from __future__ import annotations

from app.services.policy_engine import PolicyEngine


def test_policy_engine_loads_rules():
    engine = PolicyEngine()
    rules = engine.load_rules("ec2")
    assert rules
    assert any(rule.id == "EC2_SG_SSH_OPEN" for rule in rules)


def test_policy_engine_evaluates_resources():
    engine = PolicyEngine()
    rules = engine.load_rules("ec2")
    resources = [
        {
            "id": "sg-123",
            "type": "security_group",
            "region": "us-east-1",
            "ip_permissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
            "description": "default",
        }
    ]
    findings = engine.evaluate("ec2", resources)
    assert findings
    assert any(f["rule_id"] == "EC2_SG_SSH_OPEN" for f in findings)
