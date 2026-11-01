"""
Model Training Pipeline: Module A - Email Phishing & Spam Detection
Trains TF-IDF + Calibrated Logistic Regression on multi-factor features.
Outputs model artifact and evaluation report.
"""

import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, classification_report
from sklearn.pipeline import Pipeline

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, "datasets", "processed", "email_dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models", "email")
REPORT_DIR = os.path.join(BASE_DIR, "evaluation", "reports")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

def train_email_model():
    print("[Module A] Training Email Phishing & Spam Model...")
    df = pd.read_csv(DATASET_PATH)

    # Feature construction: Combine Subject + Body + Sender info
    df["combined_text"] = df["subject"].fillna("") + " " + df["body"].fillna("") + " from:" + df["sender_email"].fillna("")

    X = df["combined_text"]
    y = df["label"]

    # 70% Train, 15% Val, 15% Test
    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp)

    # Pipeline: N-gram TF-IDF + Logistic Regression with Balanced Class Weights
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=5000, sublinear_tf=True)),
        ("clf", LogisticRegression(C=2.5, max_iter=1000, class_weight="balanced", random_state=42))
    ])

    pipeline.fit(X_train, y_train)

    # Evaluation on Holdout Test Set
    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted")
    cm = confusion_matrix(y_test, y_pred, labels=["legitimate", "spam", "phishing"]).tolist()
    clf_report = classification_report(y_test, y_pred, output_dict=True)

    metrics = {
        "module": "email",
        "model_version": "email-v1.0.0",
        "algorithm": "TF-IDF (1,2-gram) + Logistic Regression",
        "dataset_size": len(df),
        "train_size": len(X_train),
        "val_size": len(X_val),
        "test_size": len(X_test),
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "confusion_matrix": cm,
        "classes": ["legitimate", "spam", "phishing"],
        "class_report": clf_report
    }

    # Save model binary
    model_path = os.path.join(MODEL_DIR, "email_model.joblib")
    joblib.dump(pipeline, model_path)

    # Save evaluation report
    report_path = os.path.join(REPORT_DIR, "email_evaluation_report.json")
    with open(report_path, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f" -> Model saved to {model_path}")
    print(f" -> Report saved to {report_path}")
    print(f" -> Test Accuracy: {acc:.4f} | F1: {f1:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f}")
    return metrics

if __name__ == "__main__":
    train_email_model()
