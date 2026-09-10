"""
Sequence Model Threshold Adaptation — Fast Version
====================================================
Only computes threshold recalibration from saved prediction CSVs.
No fine-tuning required. Runs in seconds.

Usage:
    /home/tan/anaconda3/envs/kangal/bin/python3 adaptation_sequence_thresh.py
"""

from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import (
    f1_score, roc_auc_score, average_precision_score, confusion_matrix,
)

RESULT_ROOT = Path(__file__).resolve().parent / "results"
SEQ_INFER   = RESULT_ROOT / "androzoo_sequence_inference"
ADAPT_DIR   = RESULT_ROOT / "adaptation"
ADAPT_DIR.mkdir(exist_ok=True)

N_PER_CLASS = 3_000


def compute_metrics(y_true, y_prob, threshold=0.5):
    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return {
        "macro_f1":      round(f1_score(y_true, y_pred, average="macro"), 4),
        "roc_auc":       round(roc_auc_score(y_true, y_prob), 4),
        "pr_auc":        round(average_precision_score(y_true, y_prob), 4),
        "fpr":           round(fp / (fp + tn + 1e-12), 4),
        "fnr":           round(fn / (fn + tp + 1e-12), 4),
        "benign_recall": round(tn / (tn + fp + 1e-12), 4),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


rows = []

for seq_name, csv_name in [("BiLSTM",      "androzoo_sequence_predictions_bilstm.csv"),
                            ("Transformer", "androzoo_sequence_predictions_transformer.csv")]:
    print(f"\n{seq_name}")
    pdf = pd.read_csv(SEQ_INFER / csv_name).head(N_PER_CLASS * 2)
    y   = pdf["label_bin"].to_numpy()
    p   = pdf["malware_probability"].to_numpy()

    for t in [0.50, 0.70, 0.80]:
        m = compute_metrics(y, p, threshold=t)
        if t == 0.50:
            strat = "No adaptation (baseline)"
        else:
            strat = f"Threshold recalib. (t={t:.2f})"
        m.update({"model": seq_name, "strategy": strat, "threshold": t})
        rows.append(m)
        print(f"  t={t:.2f}  F1={m['macro_f1']}  FPR={m['fpr']}  FNR={m['fnr']}")

seq_df = pd.DataFrame(rows)
out_path = ADAPT_DIR / "adaptation_summary_sequence.csv"
seq_df.to_csv(out_path, index=False)
print(f"\nSaved → {out_path}")
print(seq_df[["model", "strategy", "macro_f1", "roc_auc", "fpr", "fnr"]].to_string(index=False))
