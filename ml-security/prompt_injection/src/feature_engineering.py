"""
Phase 4 & 5: Advanced Feature Engineering and Leak-Free Scaling
Extracts 4 feature groups:
A. Text-based statistical features
B. Security-specific domain heuristic indicators
C. NLP n-gram features (Word & Char TF-IDF)
D. Structural format indicators

Provides a unified scikit-learn Pipeline / ColumnTransformer fit strictly on training splits.
"""

import os
import re
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import RobustScaler, StandardScaler, MinMaxScaler
from sklearn.pipeline import FeatureUnion, Pipeline
from scipy.sparse import hstack, csr_matrix

class SecurityDomainFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extracts 24 quantitative text, security, and structural signals as a dense array.
    """
    def __init__(self):
        # Compiled security pattern signatures
        self.override_pattern = re.compile(
            r"(?:ignore|disregard|forget|bypass|override|drop|discard|cancel|negate|stop\s+following)\s+(?:all\s+)?(?:the\s+)?(?:(?:\w+)\s+){0,2}(?:previous|prior|above|former|system|initial|developer|evaluation|safety|security|rules|instructions|prompts|directives|guidelines)",
            re.I
        )
        self.extract_prompt_pattern = re.compile(
            r"(?:repeat|print|display|output|show|reveal|leak|echo|dump)\s+(?:all\s+)?(?:your\s+)?(?:system\s+prompt|initial\s+prompt|developer\s+instructions|base\s+instructions|instructions\s+verbatim|system\s+directives|hidden\s+prompt)",
            re.I
        )
        self.extract_credential_pattern = re.compile(
            r"(?:password|credential|secret|token|api[_\s]*key|oauth|admin\s*root|private\s*key|connection\s*string)",
            re.I
        )
        self.exfiltration_pattern = re.compile(
            r"(?:send|transmit|forward|exfiltrate|upload|post\s+request|http\s+get).*(?:@|https?://|webhook\.site|ngrok)",
            re.I
        )
        self.jailbreak_pattern = re.compile(
            r"(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|switch\s+to|enter)\s+(?:dan|developer\s+mode|unrestricted|unfiltered|godmode|chaos\s+mode|chaosbot)",
            re.I
        )
        self.delimiter_pattern = re.compile(
            r"(?:<\|im_start\|>|<\|im_end\|>|\[(?:SYSTEM|DELIMITER|OVERRIDE|ADMIN|DIRECTIVE)[^\]]*\]|\[INST\]|\[\/INST\]|```system|---BEGIN (?:SYSTEM|EMAIL|DOC)---|---END (?:SYSTEM|EMAIL|DOC)---|<system>|<\/system>|<developer>|<\/developer>)",
            re.I
        )
        self.html_hidden_pattern = re.compile(
            r"(?:display\s*:\s*none|font-size\s*:\s*0|opacity\s*:\s*0|visibility\s*:\s*hidden|color\s*:\s*transparent)",
            re.I
        )
        self.markdown_image_pattern = re.compile(r"!\[[^\]]*\]\([^)]+\)", re.I)
        self.code_block_pattern = re.compile(r"```[\s\S]*?```")
        self.url_pattern = re.compile(r"https?://[^\s\"'<>]+", re.I)
        self.base64_pattern = re.compile(r"\b[A-Za-z0-9+/=]{28,}\b")
        self.invisible_chars = {"\u200B", "\u200C", "\u200D", "\u200E", "\u200F", "\uFEFF", "\u00AD"}

        self.feature_names_ = [
            "char_count", "word_count", "avg_word_length", "sentence_count",
            "token_count_est", "uppercase_ratio", "digit_ratio", "punctuation_ratio",
            "has_override", "has_prompt_extraction", "has_credential_extraction",
            "has_exfiltration", "has_jailbreak", "has_delimiter_smuggling",
            "has_html_hidden", "has_markdown_image_ping", "has_code_block",
            "url_count", "has_base64", "has_invisible_chars", "invisible_char_count",
            "exclamation_count", "question_count", "bracket_count"
        ]

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        features = []
        for text in X:
            t = str(text) if text is not None else ""
            char_count = len(t)
            words = t.split()
            word_count = len(words)
            avg_word_len = char_count / word_count if word_count > 0 else 0.0
            sentences = re.split(r"[.!?]+", t)
            sentence_count = len([s for s in sentences if s.strip()])
            token_est = char_count / 4.0

            uppers = sum(1 for c in t if c.isupper())
            digits = sum(1 for c in t if c.isdigit())
            puncts = sum(1 for c in t if not c.isalnum() and not c.isspace())

            up_ratio = uppers / char_count if char_count > 0 else 0.0
            digit_ratio = digits / char_count if char_count > 0 else 0.0
            punct_ratio = puncts / char_count if char_count > 0 else 0.0

            # Security features
            has_override = 1.0 if self.override_pattern.search(t) else 0.0
            has_prompt_ext = 1.0 if self.extract_prompt_pattern.search(t) else 0.0
            has_cred_ext = 1.0 if self.extract_credential_pattern.search(t) else 0.0
            has_exfil = 1.0 if self.exfiltration_pattern.search(t) else 0.0
            has_jailbreak = 1.0 if self.jailbreak_pattern.search(t) else 0.0
            has_delimiter = 1.0 if self.delimiter_pattern.search(t) else 0.0
            has_html_hidden = 1.0 if self.html_hidden_pattern.search(t) else 0.0
            has_md_ping = 1.0 if self.markdown_image_pattern.search(t) else 0.0
            has_code = 1.0 if self.code_block_pattern.search(t) else 0.0
            urls = self.url_pattern.findall(t)
            has_b64 = 1.0 if self.base64_pattern.search(t) else 0.0
            invis_count = sum(t.count(c) for c in self.invisible_chars)

            exclamation_count = float(t.count("!"))
            question_count = float(t.count("?"))
            bracket_count = float(sum(t.count(b) for b in ["[", "]", "<", ">", "{", "}"]))

            row = [
                float(char_count), float(word_count), float(avg_word_len), float(sentence_count),
                float(token_est), float(up_ratio), float(digit_ratio), float(punct_ratio),
                has_override, has_prompt_ext, has_cred_ext,
                has_exfil, has_jailbreak, has_delimiter,
                has_html_hidden, has_md_ping, has_code,
                float(len(urls)), has_b64, 1.0 if invis_count > 0 else 0.0, float(invis_count),
                exclamation_count, question_count, bracket_count
            ]
            features.append(row)

        return np.array(features, dtype=np.float32)

    def get_feature_names_out(self, input_features=None):
        return np.array(self.feature_names_)


def build_feature_pipeline(scaler_type="robust", max_word_features=3000, max_char_features=2000):
    """
    Builds a composite feature extraction pipeline combining:
    1. Word-level TF-IDF (1-3 ngrams)
    2. Character-level TF-IDF (3-5 ngrams)
    3. Scaled domain & security features
    """
    scalers = {
        "robust": RobustScaler(),
        "standard": StandardScaler(),
        "minmax": MinMaxScaler()
    }
    chosen_scaler = scalers.get(scaler_type, RobustScaler())

    word_tfidf = TfidfVectorizer(
        ngram_range=(1, 3),
        max_features=max_word_features,
        sublinear_tf=True
    )
    char_tfidf = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=max_char_features,
        sublinear_tf=True
    )
    domain_pipeline = Pipeline([
        ("domain_extractor", SecurityDomainFeatureExtractor()),
        ("scaler", chosen_scaler)
    ])

    return word_tfidf, char_tfidf, domain_pipeline
