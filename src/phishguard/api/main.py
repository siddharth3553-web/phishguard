"""Uvicorn entry: `uvicorn phishguard.api.main:app`."""

from phishguard.api.app import create_app

app = create_app()
