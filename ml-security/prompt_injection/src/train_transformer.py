"""
Phase 6: Advanced NLP Model Training - DistilBERT Fine-Tuning
Fine-tunes distilbert-base-uncased on Apple Silicon MPS / CPU.
Evaluates on untouched holdout test set and exports to models/transformer/.
"""

import os
import json
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification, get_linear_schedule_with_warmup
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import time

DATASET_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../datasets/processed/preprocessed_dataset.parquet"))
MODEL_OUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../models/transformer"))
REPORTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../reports"))

os.makedirs(MODEL_OUT_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


class PromptDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_len=128):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding="max_length",
            max_length=self.max_len,
            return_tensors="pt"
        )
        item = {key: val.squeeze(0) for key, val in encoding.items()}
        item["labels"] = torch.tensor(self.labels[idx], dtype=torch.long)
        return item


def train_distilbert():
    device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    print(f"[Phase 6 Transformer] Using computation device: {device}")

    df = pd.read_parquet(DATASET_PATH)
    X = np.array(df["clean_text"].tolist(), dtype=object)
    y = np.array(df["label"].tolist(), dtype=int)

    # Stratified 70/15/15 splits matching baseline models
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.1765, random_state=42, stratify=y_train_val
    )

    model_name = "distilbert-base-uncased"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    model.to(device)

    train_dataset = PromptDataset(X_train, y_train, tokenizer, max_len=128)
    val_dataset = PromptDataset(X_val, y_val, tokenizer, max_len=128)
    test_dataset = PromptDataset(X_test, y_test, tokenizer, max_len=128)

    train_loader = DataLoader(train_dataset, batch_size=16, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)

    # Class weighting for balanced loss
    n_pos = sum(y_train)
    n_neg = len(y_train) - n_pos
    pos_weight = torch.tensor([1.0, float(n_neg / n_pos)], dtype=torch.float32).to(device)
    loss_fn = torch.nn.CrossEntropyLoss(weight=pos_weight)

    epochs = 3
    optimizer = torch.optim.AdamW(model.parameters(), lr=2e-5, weight_decay=0.01)
    total_steps = len(train_loader) * epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=int(total_steps * 0.1), num_training_steps=total_steps)

    print(f"[Training] Starting DistilBERT fine-tuning across {epochs} epochs...")
    best_val_f1 = 0.0

    for epoch in range(epochs):
        model.train()
        total_train_loss = 0.0
        for batch in train_loader:
            optimizer.zero_grad()
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            loss = loss_fn(outputs.logits, labels)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            total_train_loss += loss.item()

        # Validation evaluation
        model.eval()
        val_preds, val_targets = [], []
        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch["input_ids"].to(device)
                attention_mask = batch["attention_mask"].to(device)
                labels = batch["labels"].to(device)
                outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                preds = torch.argmax(outputs.logits, dim=1).cpu().numpy()
                val_preds.extend(preds)
                val_targets.extend(labels.cpu().numpy())

        val_f1 = f1_score(val_targets, val_preds)
        print(f"Epoch {epoch+1}/{epochs} | Train Loss: {total_train_loss/len(train_loader):.4f} | Val F1: {val_f1:.4f}")
        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            model.save_pretrained(MODEL_OUT_DIR)
            tokenizer.save_pretrained(MODEL_OUT_DIR)

    # ----------------------------------------------------
    # Evaluate on Untouched Holdout Test Set
    # ----------------------------------------------------
    print("[Evaluation] Evaluating fine-tuned DistilBERT on untouched holdout test set...")
    model.eval()
    test_preds, test_probs, test_targets = [], [], []
    t_start = time.time()

    with torch.no_grad():
        for batch in test_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            probs = torch.softmax(outputs.logits, dim=1)[:, 1].cpu().numpy()
            preds = torch.argmax(outputs.logits, dim=1).cpu().numpy()

            test_probs.extend(probs)
            test_preds.extend(preds)
            test_targets.extend(labels.cpu().numpy())

    inference_ms = (time.time() - t_start) / len(test_targets) * 1000

    acc = float(accuracy_score(test_targets, test_preds))
    prec = float(precision_score(test_targets, test_preds, zero_division=0))
    rec = float(recall_score(test_targets, test_preds, zero_division=0))
    f1 = float(f1_score(test_targets, test_preds, zero_division=0))
    roc_auc = float(roc_auc_score(test_targets, test_probs))
    cm = confusion_matrix(test_targets, test_preds).tolist()

    tn, fp, fn, tp = confusion_matrix(test_targets, test_preds).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    transformer_metrics = {
        "model": "DistilBERT (Fine-Tuned)",
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "avg_latency_ms": round(inference_ms, 2),
        "confusion_matrix": cm,
        "counts": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
    }

    print("\n================== DistilBERT Test Results ==================")
    print(f"Accuracy:  {acc:.2%}")
    print(f"Precision: {prec:.2%}")
    print(f"Recall:    {rec:.2%}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"ROC-AUC:   {roc_auc:.4f}")
    print(f"Avg Inference Latency: {inference_ms:.2f}ms / sample")
    print("=============================================================")

    # Save transformer evaluation report
    report_path = os.path.join(REPORTS_DIR, "transformer_evaluation.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(transformer_metrics, f, indent=2)

    print(f"[Phase 6 Transformer Complete] Artifacts saved to: {MODEL_OUT_DIR}")


if __name__ == "__main__":
    train_distilbert()
