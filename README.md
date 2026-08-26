# PhishGuard

Offline ML phishing detector for **URLs** and **emails**, with a Streamlit demo UI.

- URL path: lexical / structural features → StandardScaler → Random Forest  
- Email path: hybrid TF-IDF (word + char) + numeric signals → SGDClassifier (`log_loss`)  
- Configurable verdict thresholds in `src/phishguard/settings.py`  
- Synthetic datasets (no API keys, runs fully offline)

## Stack

Python 3.10+ · scikit-learn · pandas · Streamlit · Plotly · tldextract · pytest · ruff

## Project layout

| Path | Purpose |
|------|---------|
| `src/phishguard/` | Package (`paths`, `settings`, feature extractors, predictor) |
| `apps/streamlit_app.py` | Streamlit UI |
| `app.py` | `streamlit run app.py` entrypoint |
| `scripts/` | `prepare_data.py`, `train_models.py` |
| `data/raw/` | Generated CSV training data |
| `artifacts/models/` | Trained `.pkl` models (local; gitignored) |
| `artifacts/metrics/` | Evaluation JSON for the dashboard |
| `tests/` | Unit tests |

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

make data
make train
make run
```

Open **http://localhost:8501**.

## Makefile

| Target | Action |
|--------|--------|
| `make setup` | Create `.venv` and install editable package + dev deps |
| `make data` | Generate synthetic `data/raw/*.csv` |
| `make train` | Train models → `artifacts/models` + `artifacts/metrics` |
| `make test` | Pytest |
| `make lint` | Ruff |
| `make run` | Launch Streamlit |
| `make check` | Lint + test |

## Demo (2–3 minutes)

1. **URL Scanner** — try Safe / Phishing examples; inspect features and verdict.  
2. **Email Scanner** — paste message text; review score and keyword flags.  
3. **Dashboard** — confusion matrices and feature importances (after `make train`).

## Security notes

- Load only joblib artifacts you produced with `make train`. Do not load untrusted pickles.  
- `tldextract` may fetch the public suffix list on first use.  
- Streamlit is for local / controlled demos — add auth and TLS before any public exposure.

## License

MIT © Siddhartha Venkatesan
