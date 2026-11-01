"""
Model Training Pipeline: Module C - Prompt Injection & Adversarial Jailbreak Detection
Trains multi-feature N-gram TF-IDF + Logistic Classifier for adversarial prompt vectors.
Outputs model artifact and evaluation report.
"""

import os
import json
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, roc_auc_score
from sklearn.pipeline import Pipeline

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, "datasets", "processed", "injection_dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models", "injection")
REPORT_DIR = os.path.join(BASE_DIR, "evaluation", "reports")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

def train_injection_model():
    print("[Module C] Training Prompt Injection Model...")
    df = pd.read_csv(DATASET_PATH)

    X = df["text"]
    y = df["label"].map({"benign": 0, "injection": 1})

    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp)

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 3), max_features=8000, sublinear_tf=True)),
        ("clf", LogisticRegression(C=3.0, max_iter=1000, class_weight="balanced", random_state=42))
    ])

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary")
    roc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred).tolist()

    metrics = {
        "module": "injection",
        "model_version": "injection-v1.0.0",
        "algorithm": "N-gram TF-IDF (1,3-gram) + Logistic Classifier",
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
        "classes": ["benign", "injection"]
    }

    model_path = os.path.join(MODEL_DIR, "injection_model.joblib")
    joblib.dump(pipeline, model_path)

    report_path = os.path.join(REPORT_DIR, "injection_evaluation_report.json")
    with open(report_path, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f" -> Model saved to {model_path}")
    print(f" -> Report saved to {report_path}")
    print(f" -> Test Accuracy: {acc:.4f} | F1: {f1:.4f} | Recall: {rec:.4f}")
    return metrics

if __name__ == "__main__":
    train_injection_model()
