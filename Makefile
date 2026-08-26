.PHONY: setup install data train test lint run run-app check

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

test:
	$(PY) -m pytest tests/ -q

lint:
	$(PY) -m ruff check src tests scripts apps

run:
	$(PY) -m streamlit run apps/streamlit_app.py --server.headless true

run-app:
	$(PY) -m streamlit run app.py --server.headless true

check: lint test
	@echo "OK"
