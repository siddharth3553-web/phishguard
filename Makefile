.PHONY: setup install data train test lint api run up down check fixtures

PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/pip
PY := $(VENV)/bin/python

setup:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install -U pip
	$(PIP) install -e ".[dev]"

install:
	$(PIP) install -e ".[dev]"

data:
	$(PY) scripts/prepare_data.py

train:
	$(PY) scripts/train_models.py

fixtures:
	$(PY) scripts/build_fixture_models.py

test:
	$(PY) -m pytest tests/ -q

lint:
	$(PY) -m ruff check src tests scripts apps

api:
	$(PY) -m uvicorn phishguard.api.main:app --reload --port 8000

run:
	PHISHGUARD_API_URL=http://127.0.0.1:8000 $(PY) -m streamlit run apps/streamlit_app.py --server.headless true

up:
	docker compose up --build

down:
	docker compose down

check: lint test
	@echo "OK"
