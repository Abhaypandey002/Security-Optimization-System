from __future__ import annotations

from app.services.policy_engine import PolicyEngine
from app.services.rules import ec2


def test_security_group_rule_detects_open_port():
    rule = PolicyEngine().load_rules("ec2")[0]
    resources = [
        {
            "id": "sg-123",
            "type": "security_group",
            "region": "us-east-1",
            "name": "default",
            "description": "default group",
            "ip_permissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        }
    ]
    findings = ec2.security_group_rule(rule, resources)
    assert findings
    assert findings[0]["evidence"]["exposures"][0]["from_port"] == 22


def test_instance_metadata_rule_flags_imdsv1():
    rule = next(r for r in PolicyEngine().load_rules("ec2") if r.id == "EC2_IMDSV2_ENFORCED")
    resources = [
        {
            "id": "i-123",
            "type": "instance",
            "region": "us-east-1",
            "metadata_options": {"HttpTokens": "optional"},
            "public_ip": None,
        }
    ]
    findings = ec2.instance_metadata_rule(rule, resources)
    assert findings
    assert findings[0]["evidence"]["http_tokens"] == "optional"


def test_volume_encryption_rule_identifies_unencrypted():
    rule = next(r for r in PolicyEngine().load_rules("ec2") if r.id == "EC2_EBS_ENCRYPTION")
    resources = [
        {
            "id": "vol-123",
            "type": "ebs_volume",
            "region": "us-east-1",
            "encrypted": False,
            "attachments": [],
        }
    ]
    findings = ec2.volume_encryption_rule(rule, resources)
    assert findings
    assert findings[0]["severity"] == rule.severity
