.PHONY: setup sync data train test lint api web up down check fixtures

UV ?= uv

setup: sync

sync:
	$(UV) sync --extra dev

data:
	$(UV) run python scripts/prepare_data.py

train:
	$(UV) run python scripts/train_models.py

fixtures:
	$(UV) run python scripts/build_fixture_models.py

test:
	$(UV) run pytest tests/ -q

lint:
	$(UV) run ruff check src tests scripts

api:
	$(UV) run uvicorn phishguard.api.main:app --reload --port 8000

web:
	cd web && npm run dev

up:
	docker compose up --build

down:
	docker compose down

check: lint test
	@echo "OK"
