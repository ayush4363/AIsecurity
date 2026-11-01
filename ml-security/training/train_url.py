"""
Model Training Pipeline: Module B - Malicious & Phishing URL Detection
Trains Random Forest on structural and lexical URL features.
Outputs model artifact and evaluation report.
"""

import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, roc_auc_score, classification_report

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, "datasets", "processed", "url_dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models", "url")
REPORT_DIR = os.path.join(BASE_DIR, "evaluation", "reports")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

FEATURE_COLS = [
    "url_length", "is_https", "is_ip", "subdomain_count",
    "has_at", "has_hyphen", "suspicious_keyword_count"
]

def train_url_model():
    print("[Module B] Training Malicious URL Random Forest Model...")
    df = pd.read_csv(DATASET_PATH)

    X = df[FEATURE_COLS]
    y = df["label"]

    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp)

    clf = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42, class_weight="balanced")
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary")
    roc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred).tolist()

    metrics = {
        "module": "url",
        "model_version": "url-v1.0.0",
        "algorithm": "Random Forest Classifier (100 Trees)",
        "features": FEATURE_COLS,
        "dataset_size": len(df),
        "train_size": len(X_train),
        "val_size": len(X_val),
        "test_size": len(X_test),
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "roc_auc": round(float(roc), 4),
        "confusion_matrix": cm,
        "classes": ["benign", "malicious"]
    }

    model_path = os.path.join(MODEL_DIR, "url_model.joblib")
    joblib.dump({"model": clf, "features": FEATURE_COLS}, model_path)

    report_path = os.path.join(REPORT_DIR, "url_evaluation_report.json")
    with open(report_path, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f" -> Model saved to {model_path}")
    print(f" -> Report saved to {report_path}")
    print(f" -> Test Accuracy: {acc:.4f} | F1: {f1:.4f} | ROC-AUC: {roc:.4f}")
    return metrics

if __name__ == "__main__":
    train_url_model()
