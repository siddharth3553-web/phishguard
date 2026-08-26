"""Sklearn transformer: word + char TF-IDF + numeric features → sparse matrix."""

from __future__ import annotations

from typing import Any

import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

from phishguard.services.email_features import clean_email_text
from phishguard.services.email_numeric import extract_email_numeric_features


class EmailFeatureMixer(BaseEstimator, TransformerMixin):
    """Hybrid text + heuristic features for phishing email classification."""

    def __init__(
        self,
        word_max_features: int = 12_000,
        char_max_features: int = 6_000,
        min_df_word: int = 1,
        min_df_char: int = 1,
    ) -> None:
        self.word_max_features = word_max_features
        self.char_max_features = char_max_features
        self.min_df_word = min_df_word
        self.min_df_char = min_df_char
        self._word = TfidfVectorizer(
            max_features=word_max_features,
            ngram_range=(1, 2),
            min_df=min_df_word,
            stop_words="english",
            sublinear_tf=True,
            strip_accents="unicode",
        )
        self._char = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            min_df=min_df_char,
            max_features=char_max_features,
            sublinear_tf=True,
            strip_accents="unicode",
        )
        self._num_scaler = StandardScaler()

    def fit(self, X: Any, y: Any = None) -> EmailFeatureMixer:
        texts = list(X)
        cleaned = [clean_email_text(t) for t in texts]
        self._word.fit(cleaned)
        self._char.fit(cleaned)
        num = np.vstack([extract_email_numeric_features(t) for t in texts])
        self._num_scaler.fit(num)
        return self

    def transform(self, X: Any) -> csr_matrix:
        texts = list(X)
        cleaned = [clean_email_text(t) for t in texts]
        w = self._word.transform(cleaned)
        c = self._char.transform(cleaned)
        num = self._num_scaler.transform(
            np.vstack([extract_email_numeric_features(t) for t in texts])
        )
        return hstack([w, c, csr_matrix(num)], format="csr")
