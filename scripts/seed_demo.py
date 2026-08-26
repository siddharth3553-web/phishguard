#!/usr/bin/env python3
"""Seed demo users: employee@demo.local / analyst@demo.local."""

from phishguard.core.config import get_settings
from phishguard.db.session import init_db
from phishguard.services.seed import seed_demo_data

if __name__ == "__main__":
    settings = get_settings()
    init_db(settings)
    seed_demo_data(settings)
    print("Seeded employee@demo.local / employee123 and analyst@demo.local / analyst123")
