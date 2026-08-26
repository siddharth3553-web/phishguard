"""PhishGuard Streamlit UI — run: streamlit run apps/streamlit_app.py (from project root)."""

from __future__ import annotations

import json
import logging
import os

import httpx
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from phishguard.paths import metrics_dir

API_BASE = os.environ.get("PHISHGUARD_API_URL", "http://127.0.0.1:8000").rstrip("/")

logger = logging.getLogger(__name__)

st.set_page_config(
    page_title="PhishGuard - AI Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        text-align: center;
        padding: 1rem 0;
    }
    .sub-header {
        font-size: 1.1rem;
        text-align: center;
        color: #888;
        margin-bottom: 2rem;
    }
    .verdict-safe {
        background-color: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        font-size: 1.3rem;
        font-weight: 600;
    }
    .verdict-suspicious {
        background-color: #fff3cd;
        color: #856404;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        font-size: 1.3rem;
        font-weight: 600;
    }
    .verdict-phishing {
        background-color: #f8d7da;
        color: #721c24;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        font-size: 1.3rem;
        font-weight: 600;
    }
    .verdict-uncertain {
        background-color: #e2e3e5;
        color: #383d41;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        font-size: 1.3rem;
        font-weight: 600;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 10px 24px;
        font-weight: 500;
    }
</style>
""",
    unsafe_allow_html=True,
)


def _api_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    key = os.environ.get("API_KEY")
    if key:
        headers["X-API-Key"] = key
    return headers


def api_post(path: str, payload: dict) -> dict:
    url = f"{API_BASE}{path}"
    with httpx.Client(timeout=30.0) as client:
        response = client.post(url, json=payload, headers=_api_headers())
        response.raise_for_status()
        return response.json()


def load_metrics(filename: str):
    path = os.path.join(metrics_dir(), filename)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return None


def make_gauge(score: float, title: str):
    if score < 30:
        color = "green"
    elif score < 70:
        color = "orange"
    else:
        color = "red"

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number+delta",
            value=score,
            title={"text": title, "font": {"size": 18}},
            number={"suffix": "%", "font": {"size": 36}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1},
                "bar": {"color": color},
                "bgcolor": "white",
                "steps": [
                    {"range": [0, 30], "color": "#d4edda"},
                    {"range": [30, 70], "color": "#fff3cd"},
                    {"range": [70, 100], "color": "#f8d7da"},
                ],
                "threshold": {
                    "line": {"color": "black", "width": 3},
                    "thickness": 0.8,
                    "value": score,
                },
            },
        )
    )
    fig.update_layout(height=280, margin={"t": 60, "b": 20, "l": 30, "r": 30})
    return fig


def verdict_html(verdict: str) -> str:
    key = verdict.lower().replace(" ", "-")
    css_class = f"verdict-{key}"
    icons = {
        "Safe": "✅",
        "Suspicious": "⚠️",
        "Phishing": "🚨",
        "Uncertain": "❔",
    }
    return f'<div class="{css_class}">{icons.get(verdict, "")} Verdict: {verdict}</div>'


def _set_url_safe() -> None:
    st.session_state["url_input"] = "https://www.google.com/search?q=hello"


def _set_url_phish() -> None:
    st.session_state["url_input"] = "http://192.168.1.1/login.php?id=abc123"


_EMAIL_SAFE_EXAMPLE = (
    "Hi team, please find the attached report for March. "
    "Let me know if you have any questions. Best regards, Alice."
)
_EMAIL_PHISH_EXAMPLE = (
    "URGENT: Your account has been suspended due to suspicious activity. "
    "Click here to verify your identity immediately: "
    "http://secureverify.xyz/confirm?id=8a7b3c. "
    "If you do not act within 24 hours, your account will be permanently locked."
)


def _set_email_safe() -> None:
    st.session_state["email_input"] = _EMAIL_SAFE_EXAMPLE


def _set_email_phish() -> None:
    st.session_state["email_input"] = _EMAIL_PHISH_EXAMPLE


st.markdown('<div class="main-header">🛡️ PhishGuard</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">AI-Driven Phishing Detection System &mdash; URL &amp; Email Analysis</div>',
    unsafe_allow_html=True,
)

tab_home, tab_url, tab_email, tab_dash = st.tabs(
    ["🏠 Home", "🔗 URL Scanner", "📧 Email Scanner", "📊 Dashboard"]
)

with tab_home:
    st.markdown("## About PhishGuard")
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown(
            """
        **PhishGuard** is an AI-powered phishing detection system that protects users from
        malicious URLs and fraudulent emails using machine learning.

        ### How It Works
        - **URL Analysis**: Extracts 25+ lexical / structural / TLD-risk features from any URL and
          classifies with a tuned Random Forest (cross-validated hyperparameters).
        - **Email Analysis**: Hybrid word + character TF‑IDF plus heuristic signals, trained with a
          linear classifier for robustness on noisy text.

        ### Key Features
        - Real-time threat scoring with confidence percentage
        - Visual gauge charts for intuitive risk assessment
        - Detailed feature breakdown for URL analysis
        - Phishing keyword detection in emails
        - Model performance dashboard with metrics

        ### Tech Stack
        | Component | Technology |
        |-----------|-----------|
        | API | FastAPI + Pydantic v2 + SQLite |
        | UI | Streamlit (HTTP client) |
        | ML | Random Forest (URL), hybrid TF‑IDF (email) |
        | Ops | /health /ready /metrics, Docker Compose |
        """
        )
    with col2:
        st.markdown("### Architecture")
        st.code(
            """
User Input
    │
    ├─ URL ──► Feature
    │         Extraction
    │            │
    │         Random Forest
    │            │
    │         Threat Score
    │
    └─ Email ► Hybrid TF‑IDF
                 │   + heuristics
              Linear classifier
                 │
              Threat Score
        """,
            language=None,
        )
        st.markdown("### Quick Start")
        st.info("👈 Select **URL Scanner** or **Email Scanner** tab to begin analysis.")

with tab_url:
    st.markdown("## 🔗 URL Phishing Scanner")
    st.markdown("Enter a URL below to analyze it for phishing indicators.")

    # Buttons must use on_click and appear *before* the keyed text_input so session_state
    # is not mutated after the widget is instantiated (StreamlitAPIException).
    st.markdown("**Try these:**")
    ex_u1, ex_u2 = st.columns(2)
    with ex_u1:
        st.button("Safe Example", key="safe_url", on_click=_set_url_safe)
    with ex_u2:
        st.button("Phishing Example", key="phish_url", on_click=_set_url_phish)

    url_input = st.text_input(
        "Enter URL to analyze",
        placeholder="e.g. https://g00gle.xyz/login/verify",
        key="url_input",
    )

    if url_input:
        try:
            result = api_post("/api/v1/urls/scans", {"url": url_input})

            st.markdown("---")
            col_gauge, col_verdict = st.columns([1, 1])

            with col_gauge:
                fig = make_gauge(result["phishing_score"], "Phishing Threat Score")
                st.plotly_chart(fig, use_container_width=True)

            with col_verdict:
                st.markdown(verdict_html(result["verdict"]), unsafe_allow_html=True)
                st.markdown("")
                st.metric("Confidence", f"{result['confidence']}%")
                st.metric("Phishing Probability", f"{result['phishing_score']}%")
                if result.get("note"):
                    st.caption(result["note"])
                if result.get("low_confidence"):
                    st.warning("Low model confidence — treat this as advisory.")

            if result.get("features"):
                st.markdown("### Extracted Features")
                feat_df = pd.DataFrame(
                    list(result["features"].items()),
                    columns=["Feature", "Value"],
                )
                col_feat1, col_feat2 = st.columns(2)
                half = len(feat_df) // 2
                with col_feat1:
                    st.dataframe(feat_df.iloc[:half], use_container_width=True, hide_index=True)
                with col_feat2:
                    st.dataframe(feat_df.iloc[half:], use_container_width=True, hide_index=True)
            elif result.get("insufficient_input"):
                st.info("Enter a longer URL to see extracted features.")

        except Exception:
            logger.exception("URL analysis failed")
            st.error(
                f"API unreachable at {API_BASE}. Start it with `make api` "
                "(after `make train`) and retry."
            )

with tab_email:
    st.markdown("## 📧 Email Phishing Scanner")
    st.markdown("Paste email content below to check for phishing indicators.")

    st.markdown("**Try these:**")
    ex_e1, ex_e2 = st.columns(2)
    with ex_e1:
        st.button("Safe Example", key="safe_email", on_click=_set_email_safe)
    with ex_e2:
        st.button("Phishing Example", key="phish_email", on_click=_set_email_phish)

    email_input = st.text_area(
        "Paste email content",
        height=200,
        placeholder="Paste the email body text here...",
        key="email_input",
    )

    if email_input:
        try:
            result = api_post("/api/v1/emails/scans", {"text": email_input})

            st.markdown("---")
            col_gauge_e, col_verdict_e = st.columns([1, 1])

            with col_gauge_e:
                fig = make_gauge(result["phishing_score"], "Phishing Threat Score")
                st.plotly_chart(fig, use_container_width=True)

            with col_verdict_e:
                st.markdown(verdict_html(result["verdict"]), unsafe_allow_html=True)
                st.markdown("")
                st.metric("Confidence", f"{result['confidence']}%")
                st.metric("Phishing Probability", f"{result['phishing_score']}%")
                if result.get("note"):
                    st.caption(result["note"])
                if result.get("low_confidence"):
                    st.warning("Low model confidence — treat this as advisory.")

            if result["flagged_keywords"]:
                st.markdown("### 🚩 Flagged Phishing Keywords")
                kw_cols = st.columns(min(len(result["flagged_keywords"]), 4))
                for i, kw in enumerate(result["flagged_keywords"]):
                    with kw_cols[i % len(kw_cols)]:
                        st.warning(f"**{kw}**")
            else:
                st.success("No known phishing keywords detected.")

        except Exception:
            logger.exception("Email analysis failed")
            st.error(
                f"API unreachable at {API_BASE}. Start it with `make api` "
                "(after `make train`) and retry."
            )

with tab_dash:
    st.markdown("## 📊 Model Performance Dashboard")

    url_metrics = load_metrics("url_metrics.json")
    email_metrics = load_metrics("email_metrics.json")

    if not url_metrics or not email_metrics:
        st.warning(
            "No model metrics found. Run `python scripts/train_models.py` first "
            "(after `python scripts/prepare_data.py`)."
        )
    else:
        st.markdown("### Overall Accuracy")
        col_m1, col_m2, col_m3, col_m4 = st.columns(4)
        with col_m1:
            st.metric("URL Model Accuracy", f"{url_metrics['report']['accuracy']:.1%}")
        with col_m2:
            st.metric("URL AUC-ROC", f"{url_metrics['auc_roc']:.4f}")
        with col_m3:
            st.metric("Email Model Accuracy", f"{email_metrics['report']['accuracy']:.1%}")
        with col_m4:
            st.metric("Email AUC-ROC", f"{email_metrics['auc_roc']:.4f}")

        st.markdown("---")

        col_cm1, col_cm2 = st.columns(2)

        with col_cm1:
            st.markdown("### URL Model - Confusion Matrix")
            cm = np.array(url_metrics["confusion_matrix"])
            fig_cm = px.imshow(
                cm,
                labels={"x": "Predicted", "y": "Actual", "color": "Count"},
                x=["Legitimate", "Phishing"],
                y=["Legitimate", "Phishing"],
                text_auto=True,
                color_continuous_scale="Blues",
            )
            fig_cm.update_layout(height=350, margin={"t": 30, "b": 20})
            st.plotly_chart(fig_cm, use_container_width=True)

        with col_cm2:
            st.markdown("### Email Model - Confusion Matrix")
            cm_e = np.array(email_metrics["confusion_matrix"])
            fig_cm_e = px.imshow(
                cm_e,
                labels={"x": "Predicted", "y": "Actual", "color": "Count"},
                x=["Legitimate", "Phishing"],
                y=["Legitimate", "Phishing"],
                text_auto=True,
                color_continuous_scale="Reds",
            )
            fig_cm_e.update_layout(height=350, margin={"t": 30, "b": 20})
            st.plotly_chart(fig_cm_e, use_container_width=True)

        st.markdown("---")

        col_fi1, col_fi2 = st.columns(2)

        with col_fi1:
            st.markdown("### URL Model - Feature Importance")
            feat_imp = url_metrics.get("feature_importances", {})
            if feat_imp:
                fi_df = pd.DataFrame(
                    sorted(feat_imp.items(), key=lambda x: x[1], reverse=True),
                    columns=["Feature", "Importance"],
                )
                fig_fi = px.bar(
                    fi_df.head(12),
                    x="Importance",
                    y="Feature",
                    orientation="h",
                    color="Importance",
                    color_continuous_scale="Viridis",
                )
                fig_fi.update_layout(
                    height=400,
                    margin={"t": 20, "b": 20},
                    yaxis={"autorange": "reversed"},
                    showlegend=False,
                )
                st.plotly_chart(fig_fi, use_container_width=True)

        with col_fi2:
            st.markdown("### Email Model - Top Keywords")
            top_words = email_metrics.get("top_words", {})
            if top_words:
                tw_df = pd.DataFrame(
                    sorted(top_words.items(), key=lambda x: x[1], reverse=True),
                    columns=["Word/Phrase", "Importance"],
                )
                fig_tw = px.bar(
                    tw_df.head(12),
                    x="Importance",
                    y="Word/Phrase",
                    orientation="h",
                    color="Importance",
                    color_continuous_scale="Magma",
                )
                fig_tw.update_layout(
                    height=400,
                    margin={"t": 20, "b": 20},
                    yaxis={"autorange": "reversed"},
                    showlegend=False,
                )
                st.plotly_chart(fig_tw, use_container_width=True)

        st.markdown("---")
        st.markdown("### Detailed Classification Reports")
        col_r1, col_r2 = st.columns(2)
        with col_r1:
            st.markdown("**URL Model**")
            report_url = url_metrics["report"]
            report_df = pd.DataFrame(
                {
                    "Class": ["Legitimate", "Phishing"],
                    "Precision": [
                        report_url["Legitimate"]["precision"],
                        report_url["Phishing"]["precision"],
                    ],
                    "Recall": [
                        report_url["Legitimate"]["recall"],
                        report_url["Phishing"]["recall"],
                    ],
                    "F1-Score": [
                        report_url["Legitimate"]["f1-score"],
                        report_url["Phishing"]["f1-score"],
                    ],
                    "Support": [
                        report_url["Legitimate"]["support"],
                        report_url["Phishing"]["support"],
                    ],
                }
            )
            st.dataframe(report_df, use_container_width=True, hide_index=True)

        with col_r2:
            st.markdown("**Email Model**")
            report_em = email_metrics["report"]
            report_df_e = pd.DataFrame(
                {
                    "Class": ["Legitimate", "Phishing"],
                    "Precision": [
                        report_em["Legitimate"]["precision"],
                        report_em["Phishing"]["precision"],
                    ],
                    "Recall": [
                        report_em["Legitimate"]["recall"],
                        report_em["Phishing"]["recall"],
                    ],
                    "F1-Score": [
                        report_em["Legitimate"]["f1-score"],
                        report_em["Phishing"]["f1-score"],
                    ],
                    "Support": [
                        report_em["Legitimate"]["support"],
                        report_em["Phishing"]["support"],
                    ],
                }
            )
            st.dataframe(report_df_e, use_container_width=True, hide_index=True)

with st.sidebar:
    st.markdown("## 🛡️ PhishGuard")
    st.markdown("---")
    st.markdown("**AI-Driven Phishing Detection**")
    st.markdown(
        "Analyzes URLs and emails using "
        "machine learning to detect phishing threats in real-time."
    )
    st.markdown("---")
    st.markdown("### Project Info")
    st.markdown(f"- **API:** `{API_BASE}`")
    st.markdown("- **Models:** Random Forest + hybrid TF‑IDF")
    st.markdown("- **Persistence:** SQLite scan log")
    st.markdown("---")
    st.markdown(
        "<small>FastAPI + Streamlit client. Open /docs on the API.</small>",
        unsafe_allow_html=True,
    )
