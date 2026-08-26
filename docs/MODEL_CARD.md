# Model card

## Artifacts

| Task | Format | Why |
| --- | --- | --- |
| URL | `url_model.onnx` (scaler + RF) | Portable inference via ONNX Runtime |
| Email | `email_pipeline.skops` | Custom `EmailFeatureMixer` pipeline |

Custom `EmailFeatureMixer` stays in skops — hybrid TF-IDF + heuristics is a poor ONNX fit. Load via `get_untrusted_types` + trusted list.

## Training data

Synthetic URLs/emails (`scripts/prepare_data.py`). Hold-out ROC-AUC near 1.0 is a pipeline smoke test, not real-world phishing performance.

## Failure modes

- Novel phishing kits outside synthetic templates.
- Short inputs → `Uncertain`.
- Only load artifacts you produced locally or the committed fixtures.
