# AWS SecureScope

AWS SecureScope is an agentless security posture management platform that audits AWS environments with a heavy focus on EC2 and EKS hardening. The system ingests short-lived AWS access keys over HTTPS, shards scans per region, runs opinionated rules against discovered resources, and generates remediation guidance with an on-premises Mistral language model. Credentials are never written to disk and expire from memory immediately after the scan.

> **Highlights**
> - Deep EC2 coverage (IMDSv2 enforcement, security group misconfigurations, instance profile analysis, EBS/snapshot encryption, patch hygiene).
> - Opinionated EKS checks (endpoint exposure, control plane logging, version skew, IRSA adoption).
> - Declarative rule catalog with 50+ controls mapped to CIS AWS Foundations and CIS Amazon EKS benchmarks.
> - FastAPI backend with Celery workers, PostgreSQL persistence, Redis queues, and TLS-by-default APIs.
> - Next.js App Router front-end with TailwindCSS + shadcn/ui, global severity filters, and Markdown/JSON exports.
> - Mistral 7B inference via llama.cpp for explainable remediation steps without leaking identifiers.

## Threat model & data handling

- **Credential intake**: Access keys and optional STS parameters are POSTed over HTTPS and validated with `sts:GetCallerIdentity` before any work begins. Keys are held only in memory using an ephemeral in-process/Redis cache with aggressive TTL. They are never persisted to disk or logs.
- **Data privacy**: Findings store anonymized resource hashes instead of raw identifiers. LLM prompts contain only redacted evidence (risk categories, severities, configuration hints) and exclude ARNs, hostnames, or account numbers.
- **Transport security**: All HTTP listeners (backend, frontend, proxy) enforce TLS 1.2+ with self-signed certificates for local development. Caddy terminates TLS and forwards traffic internally.
- **Permission minimization**: Startup validates the minimal read-only IAM policy (below). If permissions are missing, collectors log graceful warnings and the overall scan continues.

## Architecture

```
frontend (Next.js)  <--TLS-->  Caddy reverse proxy  <--TLS-->  FastAPI API
                                           |                    |
                                           |                    --> Celery workers (Redis queues)
                                           |                    --> PostgreSQL (findings, runs)
                                           |                    --> Redis (ephemeral credential cache)
                                           --> llama.cpp Mistral server (LLM advice)
```

- **Backend**: FastAPI + SQLAlchemy + Celery. Collectors are modular per service (`app/services/aws_collectors`). Rules live in hot-reloadable YAML under `app/rules`. The `PolicyEngine` loads evaluators dynamically.
- **Orchestration**: `/api/scans/start` creates a scan record, stores credentials in memory, shards work per region, and enqueues Celery tasks. Each worker enumerates resources with boto3, evaluates rules, persists findings, and optionally enriches them with the Mistral provider.
- **Exports**: `/api/scans/{id}/export.json|md` generate deterministic reports (sample outputs in `backend/app/samples`).
- **LLM**: `LocalMistralProvider` wraps llama.cpp. Prompts are rate-limited and sanitized. The provider can be swapped by implementing the `LLMProvider` interface.

## Repository layout

```
backend/
  app/
    api/               FastAPI routers
    core/              Settings, credential vault
    db/                SQLAlchemy session helpers
    llm/               LLM provider abstraction
    models/            Declarative ORM models
    rules/             YAML catalogs + evaluators
    services/          Collectors, policy engine, orchestration
    samples/           Synthetic export artifacts
  tests/               pytest suite for rules & collectors
  requirements.txt
  Dockerfile
frontend/
  app/                 Next.js App Router views
  components/          Tailwind + shadcn/ui components
  lib/                 Axios instance, helpers
  tests/               Vitest smoke tests
  package.json, Dockerfile
infra/
  docker-compose.yml   Full production-like stack with TLS proxy
  local-https/         Self-signed cert generation script + Caddyfile
scripts/
Makefile
.github/workflows/ci.yml
```

## Prerequisites

- Docker Engine 24+
- Docker Compose Plugin 2.24+
- Python 3.11+
- Node.js 20+
- OpenSSL (for generating self-signed certificates)
- (Optional) `mkcert` if you prefer locally trusted certificates

## Quick start (local HTTPS)

1. Generate certificates (self-signed):
   ```bash
   ./infra/local-https/generate.sh
   ```
   This creates `infra/local-https/certs/dev.crt|dev.key`. Add `securescope.local` to `/etc/hosts` pointing to `127.0.0.1`.

2. Download an open-source Mistral model (7B instruct). For llama.cpp, the GGUF weights can be obtained from Hugging Face:
   - https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF
   Place the desired `.gguf` file under a local directory and mount it to the compose volume (`mistral-models`).

3. Launch the stack:
   ```bash
   docker compose -f infra/docker-compose.yml up --build
   ```

4. Visit https://securescope.local (accept the self-signed certificate). FastAPI docs are at https://securescope.local/api/docs.

5. Provide read-only AWS credentials via the UI form. Optionally include a Role ARN + External ID to assume a cross-account role.

## Backend configuration

Environment variables (see `backend/.env.example`):

| Variable | Description |
| --- | --- |
| `DATABASE_URL` | SQLAlchemy connection string (PostgreSQL recommended) |
| `REDIS_URL` | Redis connection for Celery broker & credential vault |
| `LLM_ENDPOINT` | (Optional) HTTP endpoint for llama.cpp server |
| `LLM_MODEL_PATH` | Path to local `.gguf` model for on-host inference |
| `CELERY_BROKER_URL` / `CELERY_RESULT_BACKEND` | Override Celery connection strings |
| `FEATURE_FLAGS` | Comma-separated features (e.g., `llm`) |
| `ENFORCE_HTTPS` | Reject non-HTTPS traffic when `true` |

## Frontend configuration

Environment variables (see `frontend/.env.example`):

| Variable | Description |
| --- | --- |
| `NEXT_PUBLIC_API_BASE_URL` | HTTPS base URL for API requests (defaults to `https://localhost:8443`) |

## AWS read-only policy

Attach the following managed policy (or equivalent) to the IAM principal used for scanning:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "eks:List*",
        "eks:Describe*",
        "iam:List*",
        "iam:Get*",
        "organizations:DescribeOrganization",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketEncryption",
        "config:DescribeConfigurationRecorders",
        "config:DescribeDeliveryChannels",
        "cloudtrail:DescribeTrails",
        "guardduty:GetDetector",
        "securityhub:GetFindings",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

For cross-account access, create a role with this policy and require an external ID. Users can then provide their base keys plus `roleArn` and `externalId`. SecureScope will call `AssumeRole` automatically.

## Scan flow

1. **Credential validation** — FastAPI validates access by calling `sts:GetCallerIdentity`. Minimal permissions are logged to the scan record.
2. **Region discovery** — Unless users restrict to specific regions, `DescribeRegions` enumerates opt-in regions.
3. **Collector fan-out** — Celery workers fetch resource inventories (EC2 security groups, instances, EBS volumes, snapshots, EKS clusters/node groups, and global S3 data). Collectors include exponential backoff and pagination helpers.
4. **Policy evaluation** — The declarative rule engine loads 50+ controls from YAML, each referencing Python evaluators in `app/services/rules`. Evidence is normalized, hashed, and stored.
5. **LLM enrichment** — For failing rules, a sanitized JSON payload is fed to the local Mistral model, returning Markdown with rationale, remediation (CLI + console), blast radius, and regression testing guidance.
6. **Reporting** — Findings surface in the UI, via API endpoints, or via JSON/Markdown exports. Sample outputs live in `backend/app/samples`.

## Extending SecureScope

### Add a new rule

1. Create or update a YAML file under `backend/app/rules/` (e.g., `eks.yaml`). Supply metadata (`id`, `service`, `severity`, `rationale`, `references`).
2. Point `evaluation.evaluator` at a Python function under `app/services/rules/`.
3. Implement the evaluator to inspect resources and call `utils.build_finding` for failures.
4. Add pytest coverage under `backend/tests/`.

### Add a new collector/service

1. Implement a subclass of `BaseCollector` under `app/services/aws_collectors/<service>/`.
2. Register it in `CollectorRegistry.get_collectors`.
3. Provide rule definitions and tests for the new service.

### Swap LLM providers

1. Implement a new class adhering to `LLMProvider` (e.g., integrate vLLM or remote inference).
2. Update `LLMService` to instantiate your provider based on feature flags or configuration.

## Testing & quality gates

- Backend unit tests: `pytest backend/tests`
- Frontend unit tests: `npm run test` inside `frontend`
- Static analysis: `ruff check`, `mypy backend/app`, `bandit -r backend/app`, `npm run lint`
- Type checking: `npm run typecheck`
- Docker builds: `docker build -f backend/Dockerfile .` and `docker build -f frontend/Dockerfile .`
- CI pipeline (`.github/workflows/ci.yml`) enforces all of the above on push/PR.

Aim for >70% coverage on rule evaluators and collectors (pytest already covers the critical branches).

## Troubleshooting

| Issue | Fix |
| --- | --- |
| `AccessDenied` during scan | Verify the read-only policy above. SecureScope logs minimal permissions in `scan_runs.minimal_permissions`. |
| TLS warnings in browser | Import the self-signed cert (`infra/local-https/certs/dev.crt`) into your trust store or use `mkcert`. |
| LLM enrichment skipped | Ensure `LLM_MODEL_PATH` points to a `.gguf` file and llama.cpp server has access. If unset, SecureScope gracefully skips LLM output. |
| Slow scans | Use the region selector to limit scope or enable more Celery workers via `CELERY_CONCURRENCY`. |
| Rate limiting | The orchestrator caches describe calls per scan and handles throttling with backoff. Persistent throttles appear in `scan_regions.error`. |

## Compliance mapping

SecureScope maps its controls to industry benchmarks:

- **CIS AWS Foundations**: Sections 1 (identity & access), 2 (logging), 3 (monitoring), 4 (networking). Key rules: `EC2_SG_SSH_OPEN`, `EC2_EBS_ENCRYPTION`, `COMMON_S3_ENCRYPTION`.
- **CIS Amazon EKS**: Sections 2–4. Key rules: `EKS_PUBLIC_ENDPOINT_NO_CIDR`, `EKS_CONTROL_PLANE_LOGGING`, `EKS_VERSION_DRIFT_CLUSTER`.

Controls not yet automated (e.g., Config recorder enforcement) are documented in backlog issues.

## Data retention

- Credentials are removed immediately after scans complete.
- Findings, metadata, and generated advice persist in PostgreSQL for historical analysis. Purge policies can be implemented via scheduled tasks or retention settings.


