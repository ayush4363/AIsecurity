"""
Phase 3: Advanced Preprocessing Pipeline
Preserves security signals while removing duplicates, normalizing Unicode,
decoding HTML entities, extracting Base64 and URLs, and detecting invisible characters.
Maintains both original raw text and processed input text.
"""

import os
import re
import html
import unicodedata
import base64
import pandas as pd
import numpy as np

DATASET_IN = os.path.abspath(os.path.join(os.path.dirname(__file__), "../datasets/processed/prompt_injection_dataset.parquet"))
DATASET_OUT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../datasets/processed/preprocessed_dataset.parquet"))


class SecurityTextPreprocessor:
    def __init__(self):
        self.url_regex = re.compile(r"https?://[^\s\"'<>]+", re.I)
        self.base64_regex = re.compile(r"\b([A-Za-z0-9+/=]{28,})\b")
        self.invisible_chars = {"\u200B", "\u200C", "\u200D", "\u200E", "\u200F", "\uFEFF", "\u00AD"}

    def decode_html(self, text: str) -> str:
        """Decode HTML entities while keeping tags intact"""
        if not text:
            return ""
        return html.unescape(text)

    def normalize_unicode(self, text: str) -> str:
        """Apply NFKC normalization without stripping zero-width spaces"""
        if not text:
            return ""
        return unicodedata.normalize("NFKC", text)

    def detect_invisible_characters(self, text: str) -> dict:
        """Check for zero-width unicode characters used for smuggling"""
        found = [c for c in self.invisible_chars if c in text]
        return {
            "has_invisible_chars": len(found) > 0,
            "invisible_char_count": sum(text.count(c) for c in found)
        }

    def detect_base64(self, text: str) -> dict:
        """Extract and safely inspect potential Base64 encoded payload"""
        matches = self.base64_regex.findall(text)
        decoded_payloads = []
        is_suspicious_payload = False

        for m in matches:
            try:
                # Add padding if needed
                padded = m + "=" * (-len(m) % 4)
                dec = base64.b64decode(padded, validate=True).decode("utf-8", errors="ignore")
                if len(dec) >= 6 and any(c.isalnum() for c in dec):
                    decoded_payloads.append(dec)
                    if any(kw in dec.lower() for kw in ["ignore", "override", "system", "prompt", "password", "token", "delete"]):
                        is_suspicious_payload = True
            except Exception:
                pass

        return {
            "has_base64": len(matches) > 0,
            "base64_count": len(matches),
            "decoded_payloads": decoded_payloads,
            "has_adversarial_base64": is_suspicious_payload
        }

    def extract_urls(self, text: str) -> list:
        """Extract embedded URLs"""
        return self.url_regex.findall(text)

    def clean_for_model(self, text: str) -> str:
        """
        Model input representation:
        - Normalizes multiple spaces/newlines
        - Decodes HTML entities
        - Normalizes Unicode
        - PRESERVES all security punctuation: [], <>, {}, ```, ---, quotes
        """
        if not text:
            return ""
        t = self.decode_html(text)
        t = self.normalize_unicode(t)
        # Collapse excessive whitespace to single spaces
        t = re.sub(r"[ \t\r\f\v]+", " ", t)
        t = re.sub(r"\n{3,}", "\n\n", t)
        return t.strip()


def compute_jaccard_similarity(s1: str, s2: str) -> float:
    w1 = set(s1.lower().split())
    w2 = set(s2.lower().split())
    if not w1 or not w2:
        return 0.0
    return len(w1 & w2) / len(w1 | w2)


def remove_near_duplicates(df: pd.DataFrame, threshold=0.90) -> pd.DataFrame:
    """Removes near-duplicate prompts within the same class using Jaccard similarity"""
    keep_indices = []
    seen_texts = []

    for idx, row in df.iterrows():
        text = row["clean_text"]
        is_duplicate = False
        for seen in seen_texts[-150:]:  # Check sliding window of recent prompts for speed
            if compute_jaccard_similarity(text, seen) >= threshold:
                is_duplicate = True
                break
        if not is_duplicate:
            keep_indices.append(idx)
            seen_texts.append(text)

    return df.loc[keep_indices].copy()


def main():
    print("[Phase 3] Starting Advanced Preprocessing Pipeline...")
    df = pd.read_parquet(DATASET_IN)
    initial_count = len(df)

    preprocessor = SecurityTextPreprocessor()

    # 1. Generate model input representation while preserving raw original text
    df["raw_text"] = df["text"]
    df["clean_text"] = df["raw_text"].apply(preprocessor.clean_for_model)

    # 2. Extract structural & encoded security metadata
    df["urls"] = df["raw_text"].apply(preprocessor.extract_urls)
    df["url_count"] = df["urls"].apply(len)

    invis_info = df["raw_text"].apply(preprocessor.detect_invisible_characters)
    df["has_invisible_chars"] = invis_info.apply(lambda d: d["has_invisible_chars"])
    df["invisible_char_count"] = invis_info.apply(lambda d: d["invisible_char_count"])

    b64_info = df["raw_text"].apply(preprocessor.detect_base64)
    df["has_base64"] = b64_info.apply(lambda d: d["has_base64"])
    df["has_adversarial_base64"] = b64_info.apply(lambda d: d["has_adversarial_base64"])

    # 3. Filter invalid / empty records
    df = df[df["clean_text"].str.len() > 3].copy()

    # 4. Remove exact duplicates on clean_text
    df = df.drop_duplicates(subset=["clean_text"]).copy()
    exact_dedup_count = len(df)

    # 5. Near-duplicate removal
    df = remove_near_duplicates(df, threshold=0.92)
    final_count = len(df)

    # Reset IDs
    df = df.reset_index(drop=True)
    df["id"] = [f"pi-prep-{i:05d}" for i in range(len(df))]

    # Save preprocessed dataset in CSV and Parquet
    df.to_parquet(DATASET_OUT, index=False)
    csv_out = DATASET_OUT.replace(".parquet", ".csv")
    df.to_csv(csv_out, index=False)

    print(f"[Phase 3 Complete] Processed {initial_count} -> {exact_dedup_count} (exact dedup) -> {final_count} (near dedup)")
    print(f"[Phase 3] Output saved to: {DATASET_OUT}")


if __name__ == "__main__":
    main()
