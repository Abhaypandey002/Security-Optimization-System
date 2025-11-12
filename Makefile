.PHONY: setup format lint test migrate dev

setup:
python3 -m venv .venv && . .venv/bin/activate && pip install -r backend/requirements.txt && cd frontend && npm install

format:
ruff check --fix backend/app backend/tests && cd frontend && npx eslint --fix .

lint:
ruff check backend/app backend/tests && cd frontend && npm run lint

mypy:
mypy backend/app

bandit:
bandit -r backend/app

pytest:
pytest backend/tests

vitest:
cd frontend && npm run test

test: pytest vitest

migrate:
alembic -c backend/alembic.ini upgrade head

dev:
docker compose -f infra/docker-compose.yml up --build
