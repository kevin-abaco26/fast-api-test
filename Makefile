.PHONY: install dev migrate migrate-down revision lint test up down logs

install:
	uv sync

dev:
	uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8001

migrate:
	uv run alembic upgrade head

migrate-down:
	uv run alembic downgrade -1

revision:
	uv run alembic revision --autogenerate -m "$(msg)"

lint:
	uv run ruff check app tests
	uv run ruff format --check app tests

lint-fix:
	uv run ruff check --fix app tests
	uv run ruff format app tests

test:
	uv run pytest tests/ -v

test-cov:
	uv run pytest tests/ -v --tb=short

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f app
