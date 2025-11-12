# Scan 00000000-0000-0000-0000-000000000000

## Summary
Status: COMPLETED
Total Findings: 11

## Findings
### EC2_SG_SSH_OPEN (EC2)
Severity: CRITICAL
Region: us-east-1
Evidence:
````json
{
  "exposures": [
    {
      "protocol": "tcp",
      "from_port": 22,
      "to_port": 22,
      "cidr": "0.0.0.0/0"
    }
  ],
  "security_group": "open-ssh",
  "description": "SSH from anywhere"
}
````
