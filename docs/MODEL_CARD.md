# Model card

## Artifacts

| Task | Format | Why |
| --- | --- | --- |
| URL | `url_model.onnx` (scaler + RF) | Framework-agnostic, no pickle exec |
| Email | `email_pipeline.skops` | Safer than joblib for custom transformers |

Custom `EmailFeatureMixer` is not ONNX-exported (conversion of hybrid TF-IDF + heuristics is brittle). skops + `get_untrusted_types` is the honest path.

## Training data

Synthetic URLs/emails (`scripts/prepare_data.py`). Hold-out ROC-AUC near 1.0 is a pipeline smoke test, not real-world phishing performance.

## Failure modes

- Novel phishing kits outside synthetic templates.
- Short inputs → `Uncertain`.
- Only load artifacts you produced locally or the committed fixtures.
