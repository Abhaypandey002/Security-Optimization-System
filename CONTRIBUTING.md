# Contributing to AWS SecureScope

Thanks for investing time in improving SecureScope! This document outlines how to get a development environment running and the quality gates we expect.

## Development workflow

1. Fork the repository and create a feature branch.
2. Install dependencies:
   ```bash
   make setup
   ```
3. Generate local HTTPS certificates:
   ```bash
   ./infra/local-https/generate.sh
   ```
4. Start the stack:
   ```bash
   make dev
   ```

## Coding standards

- Backend uses Python 3.11 with FastAPI, SQLAlchemy, Celery, and boto3.
- Frontend uses Next.js (App Router), TypeScript, TailwindCSS, and shadcn/ui primitives.
- Run `make format` before pushing. CI runs `ruff`, `mypy`, `pytest`, `bandit`, `npm run lint`, and `npm run test`.
- Never log or persist AWS credentials. Credentials must stay in-memory for the active scan only.
- Enforce TLS for every HTTP listener; self-signed certificates are acceptable for local dev.

## Pull request checklist

- [ ] Tests added or updated with coverage for new logic.
- [ ] README.md updated when behavior changes.
- [ ] Docker and CI pipelines continue to pass.
- [ ] No binary assets committed.

We follow conventional commits for history clarity, but we will squash merge if needed. Thank you for helping keep cloud environments secure!
