"""
PhishGuard entrypoint — from project root:

  streamlit run app.py

Equivalent: streamlit run apps/streamlit_app.py
"""

from __future__ import annotations

import runpy
from pathlib import Path

runpy.run_path(str(Path(__file__).resolve().parent / "apps" / "streamlit_app.py"), run_name="__main__")
