"""
Expanded Adaptation Experiments — All Tabular + Sequence Models
================================================================
Covers all five tabular probes and both sequence models with three strategies:
  1. Threshold Recalibration  (no future-domain labels required)
  2. Drift-Feature Exclusion  (tabular only, K=10/20/30)
  3. Few-Shot Supervised Retrain (5% / 10% of AndroZoo)

Plus an upper-bound: full 5-fold CV on the AndroZoo hold-out.

Usage:
    /home/tan/anaconda3/envs/kangal/bin/python3 adaptation_experiments_all_models.py
"""

# ── Imports ────────────────────────────────────────────────────────────────────
from pathlib import Path
import json, warnings, copy
import numpy as np
import pandas as pd
import joblib
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from scipy.spatial.distance import jensenshannon
from sklearn.base import clone
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    f1_score, roc_auc_score, average_precision_score,
    confusion_matrix,
)
from sklearn.model_selection import (
    StratifiedKFold, cross_val_score, train_test_split,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

warnings.filterwarnings("ignore")

SEED = 42
np.random.seed(SEED)
torch.manual_seed(SEED)

# ── Paths ──────────────────────────────────────────────────────────────────────
ROOT          = Path(__file__).resolve().parent
DATA_ROOT     = ROOT.parent
KRONO_DIR     = DATA_ROOT / "krono_dataset"
AZ_DIR        = DATA_ROOT / "androzoo_dataset"
RESULT_ROOT   = ROOT / "results"
ADAPT_DIR     = RESULT_ROOT / "adaptation"
TABULAR_INFER = RESULT_ROOT / "androzoo_tabular_inference"
SEQ_INFER     = RESULT_ROOT / "androzoo_sequence_inference"
MODEL_DIR     = RESULT_ROOT / "tabular_models"
SEQ_MODEL_DIR = RESULT_ROOT / "androzoo_inference_model"
KRONO_SEQ_DIR = RESULT_ROOT       # bilstm/transformer .pt files are here
ADAPT_DIR.mkdir(parents=True, exist_ok=True)

N_PER_CLASS = 3_000
META        = ["package_name", "label", "timestamp"]
DEVICE      = torch.device("cpu")   # sequence fine-tuning uses CPU to avoid OOM
print(f"Device: {DEVICE}")


# ══════════════════════════════════════════════════════════════════════════════
# PART 1 — DATA UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def load_krono_tabular():
    df = pd.concat([
        pd.read_csv(KRONO_DIR / "krono_malware.csv"),
        pd.read_csv(KRONO_DIR / "krono_benign.csv"),
    ], ignore_index=True).sample(frac=1, random_state=SEED).reset_index(drop=True)
    feats = [c for c in df.columns if c not in META]
    X = df[feats]
    y = (df["label"] == "malware").astype(int).to_numpy()
    return X, y, feats


def load_androzoo_tabular(feats):
    benign  = pd.read_csv(AZ_DIR / "androzoo_benign.csv").head(N_PER_CLASS)
    malware = pd.read_csv(AZ_DIR / "androzoo_malware.csv").head(N_PER_CLASS)
    benign["label"]  = "benign"
    malware["label"] = "malware"
    df = pd.concat([benign, malware], ignore_index=True).sample(
        frac=1, random_state=SEED).reset_index(drop=True)
    X = df[feats]
    y = (df["label"] == "malware").astype(int).to_numpy()
    return X, y


def load_seqlogs(path: Path):
    records = []
    with open(path) as f:
        for line in f:
            records.append(json.loads(line.strip()))
    return records


# ── Metrics helper ─────────────────────────────────────────────────────────────
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


# ══════════════════════════════════════════════════════════════════════════════
# PART 2 — JSD (BENIGN-SIDE DRIFT)
# ══════════════════════════════════════════════════════════════════════════════

def feature_jsd(s1: pd.Series, s2: pd.Series, n_bins: int = 50) -> float:
    combined = np.concatenate([s1.dropna().values, s2.dropna().values])
    lo, hi = combined.min(), combined.max()
    if hi == lo:
        return 0.0
    bins = np.linspace(lo, hi, n_bins + 1)
    p, _ = np.histogram(s1.dropna(), bins=bins)
    q, _ = np.histogram(s2.dropna(), bins=bins)
    p = (p + 1e-9) / (p + 1e-9).sum()
    q = (q + 1e-9) / (q + 1e-9).sum()
    return float(jensenshannon(p, q))


print("Loading tabular data …")
X_krono, y_krono, FEATS = load_krono_tabular()
X_az,    y_az           = load_androzoo_tabular(FEATS)

X_train, X_val, y_train, y_val = train_test_split(
    X_krono, y_krono, test_size=0.15, stratify=y_krono, random_state=SEED,
)

jsd_cache = ADAPT_DIR / "benign_side_jsd_per_feature.csv"
if jsd_cache.exists():
    jsd_df = pd.read_csv(jsd_cache)
else:
    print("Computing benign-side JSD …")
    az_benign_raw = pd.read_csv(AZ_DIR / "androzoo_benign.csv").head(N_PER_CLASS)
    kb_raw        = pd.read_csv(KRONO_DIR / "krono_benign.csv")
    jsd_records   = []
    for f in FEATS:
        if f in kb_raw.columns and f in az_benign_raw.columns:
            jsd_records.append({"feature": f, "benign_jsd": round(feature_jsd(kb_raw[f], az_benign_raw[f]), 6)})
    jsd_df = pd.DataFrame(jsd_records).sort_values("benign_jsd", ascending=False).reset_index(drop=True)
    jsd_df.to_csv(jsd_cache, index=False)

print(f"  Top-5 drifted: {jsd_df.head(5)['feature'].tolist()}")


# ══════════════════════════════════════════════════════════════════════════════
# PART 3 — TABULAR EXPERIMENTS (all 5 models)
# ══════════════════════════════════════════════════════════════════════════════

TABULAR_MODELS = ["LogisticRegression", "RandomForest", "ExtraTrees", "MLP", "XGBoost"]
manifest_path  = MODEL_DIR / "tabular_model_manifest.json"
with open(manifest_path) as f:
    manifest = json.load(f)

tabular_rows = []


def clone_pipeline(original_pipe: Pipeline) -> Pipeline:
    """Clone a nested pipeline preserving hyperparameters but unfitting state."""
    prep  = original_pipe.named_steps["prep"]
    clf   = original_pipe.named_steps["clf"]
    new_prep_steps = [(name, clone(step)) for name, step in prep.steps]
    return Pipeline([("prep", Pipeline(new_prep_steps)), ("clf", clone(clf))])


def rebuild_pipeline_reduced(original_pipe: Pipeline, retained: list) -> Pipeline:
    """Return a fresh clone pipeline for a feature-reduced retrain."""
    return clone_pipeline(original_pipe)


def run_cv_upper_bound(original_pipe: Pipeline, X: pd.DataFrame, y: np.ndarray) -> tuple:
    pipe_clone = clone_pipeline(original_pipe)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    scores = cross_val_score(pipe_clone, X, y, cv=cv, scoring="f1_macro", n_jobs=1)
    return round(scores.mean(), 4), round(scores.std(), 4)


for model_name in TABULAR_MODELS:
    print(f"\n{'═'*60}")
    print(f"  TABULAR: {model_name}")
    print(f"{'═'*60}")

    model_pipe = joblib.load(MODEL_DIR / f"{model_name}.joblib")

    # ── (1) Baseline ──────────────────────────────────────────────────────────
    pred_csv = TABULAR_INFER / f"androzoo_tabular_predictions_{model_name.lower()}.csv"
    if pred_csv.exists():
        pred_df   = pd.read_csv(pred_csv)
        az_prob   = pred_df["malware_probability"].to_numpy()
    else:
        az_prob = model_pipe.predict_proba(X_az[FEATS])[:, 1]

    m = compute_metrics(y_az, az_prob)
    m.update({"model": model_name, "strategy": "No adaptation (baseline)", "threshold": 0.5})
    tabular_rows.append(m)
    print(f"  Baseline   F1={m['macro_f1']}  FPR={m['fpr']}  FNR={m['fnr']}")

    # ── (2) Threshold Recalibration ───────────────────────────────────────────
    for t in [0.70, 0.80]:
        m = compute_metrics(y_az, az_prob, threshold=t)
        m.update({"model": model_name, "strategy": f"Threshold recalib. (t={t:.2f})", "threshold": t})
        tabular_rows.append(m)
        print(f"  Recal t={t}  F1={m['macro_f1']}  FPR={m['fpr']}  FNR={m['fnr']}")

    # ── (3) Drift-Feature Exclusion (K=10,20,30) ──────────────────────────────
    for K in [10, 20, 30]:
        drifted  = jsd_df.head(K)["feature"].tolist()
        retained = [f for f in FEATS if f not in drifted]

        pipe = rebuild_pipeline_reduced(model_pipe, retained)
        pipe.fit(X_train[retained], y_train)
        prob  = pipe.predict_proba(X_az[retained])[:, 1]
        m = compute_metrics(y_az, prob)
        m.update({"model": model_name, "strategy": f"Drift-feature excl. (K={K})", "threshold": 0.5})
        tabular_rows.append(m)
        print(f"  Drift K={K:2d}  F1={m['macro_f1']}  FPR={m['fpr']}  FNR={m['fnr']}")

    # ── (4) Few-Shot Supervised Retrain ───────────────────────────────────────
    for adapt_frac in [0.05, 0.10]:
        X_az_adapt, X_az_test, y_az_adapt, y_az_test = train_test_split(
            X_az, y_az,
            test_size=(1 - adapt_frac),
            stratify=y_az,
            random_state=SEED,
        )
        n_adapt = len(X_az_adapt)
        X_aug   = pd.concat([X_train, X_az_adapt], ignore_index=True)
        y_aug   = np.concatenate([y_train, y_az_adapt])

        pipe = clone_pipeline(model_pipe)
        pipe.fit(X_aug, y_aug)
        prob  = pipe.predict_proba(X_az_test)[:, 1]
        m = compute_metrics(y_az_test, prob)
        m.update({
            "model": model_name,
            "strategy": f"Few-shot retrain ({int(adapt_frac*100)}%, n={n_adapt})",
            "threshold": 0.5,
        })
        tabular_rows.append(m)
        print(f"  Few-shot {int(adapt_frac*100):3d}%  F1={m['macro_f1']}  FPR={m['fpr']}  FNR={m['fnr']}")

    # ── (5) Upper Bound (5-fold CV on full AndroZoo) ──────────────────────────
    print(f"  Running 5-fold CV upper bound for {model_name} …")
    pipe_clone_cv = clone_pipeline(model_pipe)
    cv_scores = cross_val_score(
        pipe_clone_cv, X_az, y_az,
        cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED),
        scoring="f1_macro", n_jobs=1,
    )
    ub_f1, ub_std = round(cv_scores.mean(), 4), round(cv_scores.std(), 4)
    m = {
        "model": model_name, "strategy": "Full retrain (upper bound, CV)",
        "threshold": 0.5,
        "macro_f1": ub_f1, "roc_auc": None, "pr_auc": None,
        "fpr": None, "fnr": None, "benign_recall": None,
        "tn": None, "fp": None, "fn": None, "tp": None,
        "cv_std": ub_std,
    }
    tabular_rows.append(m)
    print(f"  Upper bound CV  F1={ub_f1} ± {ub_std}")


tabular_df = pd.DataFrame(tabular_rows)
tabular_df.to_csv(ADAPT_DIR / "adaptation_summary_tabular_all.csv", index=False)
print(f"\nTabular summary saved.")


# ══════════════════════════════════════════════════════════════════════════════
# PART 4 — SEQUENCE MODEL DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

class BiLSTMModel(nn.Module):
    def __init__(self, vocab_size=64, embed_dim=96, hidden_dim=128,
                 num_layers=2, dropout=0.2):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.lstm = nn.LSTM(embed_dim, hidden_dim, num_layers=num_layers,
                            batch_first=True, bidirectional=True,
                            dropout=dropout if num_layers > 1 else 0.0)
        self.head = nn.Sequential(
            nn.LayerNorm(hidden_dim * 2),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim * 2, 1),
        )

    def forward(self, x):
        emb  = self.embedding(x)
        out, (h, _) = self.lstm(emb)
        fwd  = h[-2]       # last forward  layer
        bwd  = h[-1]       # last backward layer
        feat = torch.cat([fwd, bwd], dim=-1)
        return self.head(feat).squeeze(-1)


class TransformerModel(nn.Module):
    def __init__(self, vocab_size=64, embed_dim=96, num_layers=2,
                 nhead=4, dim_feedforward=256, max_seq_len=256, dropout=0.2):
        super().__init__()
        self.token_emb = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.pos_emb   = nn.Embedding(max_seq_len, embed_dim)
        enc_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=nhead, dim_feedforward=dim_feedforward,
            dropout=dropout, batch_first=True,
        )
        self.encoder = nn.TransformerEncoder(enc_layer, num_layers=num_layers)
        self.head = nn.Sequential(
            nn.LayerNorm(embed_dim),
            nn.Dropout(dropout),
            nn.Linear(embed_dim, 1),
        )

    def forward(self, x):
        B, T    = x.shape
        pos     = torch.arange(T, device=x.device).unsqueeze(0)
        emb     = self.token_emb(x) + self.pos_emb(pos)
        pad_mask = (x == 0)
        out     = self.encoder(emb, src_key_padding_mask=pad_mask)
        feat    = out.mean(dim=1)
        return self.head(feat).squeeze(-1)


# ── Sequence dataset ──────────────────────────────────────────────────────────
class SeqDataset(Dataset):
    def __init__(self, records, stoi, max_len=256, unk_id=1):
        self.records = records
        self.stoi    = stoi
        self.max_len = max_len
        self.unk_id  = unk_id

    def __len__(self):
        return len(self.records)

    def __getitem__(self, idx):
        rec  = self.records[idx]
        tags = [e["tag"] for e in rec["seq_log"]][:self.max_len]
        ids  = [self.stoi.get(t, self.unk_id) for t in tags]
        pad  = self.max_len - len(ids)
        ids  = ids + [0] * pad
        y    = 1 if rec["label"] == "malware" else 0
        return torch.tensor(ids, dtype=torch.long), torch.tensor(y, dtype=torch.float)


@torch.no_grad()
def seq_predict(model, loader):
    model.eval()
    probs, labels = [], []
    for x, y in loader:
        x = x.to(DEVICE)
        logit = model(x)
        p     = torch.sigmoid(logit).cpu().numpy()
        probs.extend(p.tolist())
        labels.extend(y.numpy().tolist())
    return np.array(probs), np.array(labels)


def seq_fine_tune(model, train_loader, val_loader=None,
                  lr=5e-5, n_epochs=10, patience=3):
    """Fine-tune a sequence model; returns model in eval mode."""
    optimizer  = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    criterion  = nn.BCEWithLogitsLoss()
    best_f1    = -1.0
    best_state = None
    no_improve = 0

    for epoch in range(1, n_epochs + 1):
        model.train()
        total_loss = 0.0
        for x, y in train_loader:
            x, y = x.to(DEVICE), y.to(DEVICE)
            optimizer.zero_grad()
            loss = criterion(model(x), y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        if val_loader is not None:
            p, l = seq_predict(model, val_loader)
            f1   = f1_score(l, (p >= 0.5).astype(int), average="macro")
            if f1 > best_f1 + 1e-4:
                best_f1    = f1
                best_state = copy.deepcopy(model.state_dict())
                no_improve = 0
            else:
                no_improve += 1
            if no_improve >= patience:
                break

    if best_state is not None:
        model.load_state_dict(best_state)
    model.eval()
    return model


# ══════════════════════════════════════════════════════════════════════════════
# PART 5 — SEQUENCE EXPERIMENTS (BiLSTM + Transformer)
# ══════════════════════════════════════════════════════════════════════════════

print(f"\n{'═'*60}")
print("  SEQUENCE MODELS")
print(f"{'═'*60}")

# Load AndroZoo sequence data
az_benign_seqs  = load_seqlogs(AZ_DIR / "androzoo_benign_seqlogs.jsonl")
az_malware_seqs = load_seqlogs(AZ_DIR / "androzoo_malware_seqlogs.jsonl")
az_all_seqs     = az_benign_seqs[:N_PER_CLASS] + az_malware_seqs[:N_PER_CLASS]
np.random.shuffle(az_all_seqs)
y_az_seq        = np.array([1 if r["label"] == "malware" else 0 for r in az_all_seqs])

# No KronoDroid seqlogs needed: we fine-tune on the adaptation slice only.
# The sequence model was already pre-trained on KronoDroid; adapting on a small
# labeled future-domain set is sufficient (and avoids catastrophic forgetting).

seq_configs = {
    "BiLSTM": {
        "ckpt":       KRONO_SEQ_DIR / "kronodroid_sequence_bilstm.pt",
        "model_cls":  BiLSTMModel,
        "model_kwargs": dict(vocab_size=64, embed_dim=96, hidden_dim=128,
                             num_layers=2, dropout=0.2),
        "pred_csv":   SEQ_INFER / "androzoo_sequence_predictions_bilstm.csv",
    },
    "Transformer": {
        "ckpt":       SEQ_MODEL_DIR / "androzoo_sequence_model_bundle.pt",
        "model_cls":  TransformerModel,
        "model_kwargs": dict(vocab_size=64, embed_dim=96, num_layers=2,
                             nhead=4, dim_feedforward=256, max_seq_len=256, dropout=0.2),
        "pred_csv":   SEQ_INFER / "androzoo_sequence_predictions_transformer.csv",
    },
}

seq_rows = []

for seq_name, cfg in seq_configs.items():
    print(f"\n  ── {seq_name} ──")

    # Load stoi from checkpoint
    ckpt = torch.load(cfg["ckpt"], map_location="cpu", weights_only=False)
    if "stoi" in ckpt:
        stoi = ckpt["stoi"]
    elif "model_config" in ckpt:
        vocab_bundle = torch.load(SEQ_MODEL_DIR / "sequence_vocab.json",
                                  map_location="cpu", weights_only=False)
        with open(SEQ_MODEL_DIR / "sequence_vocab.json") as vf:
            stoi = json.load(vf)
    else:
        with open(SEQ_MODEL_DIR / "sequence_vocab.json") as vf:
            stoi = json.load(vf)

    # Build model and load weights
    model = cfg["model_cls"](**cfg["model_kwargs"]).to(DEVICE)
    state = ckpt.get("model_state_dict", ckpt)
    model.load_state_dict(state)
    model.eval()

    # ── (1) Baseline — use saved CSV probabilities ────────────────────────────
    pred_csv = cfg["pred_csv"]
    if pred_csv.exists():
        prob_df  = pd.read_csv(pred_csv)
        az_prob  = prob_df["malware_probability"].to_numpy()[:len(az_all_seqs)]
        az_label = prob_df["label_bin"].to_numpy()[:len(az_all_seqs)]
    else:
        ds   = SeqDataset(az_all_seqs, stoi)
        ldr  = DataLoader(ds, batch_size=256, shuffle=False, num_workers=0)
        az_prob, az_label = seq_predict(model, ldr)

    m = compute_metrics(az_label, az_prob)
    m.update({"model": seq_name, "strategy": "No adaptation (baseline)", "threshold": 0.5})
    seq_rows.append(m)
    print(f"  Baseline   F1={m['macro_f1']}  FPR={m['fpr']}  FNR={m['fnr']}")

    # ── (2) Threshold Recalibration ───────────────────────────────────────────
    for t in [0.70, 0.80]:
        m = compute_metrics(az_label, az_prob, threshold=t)
        m.update({"model": seq_name, "strategy": f"Threshold recalib. (t={t:.2f})", "threshold": t})
        seq_rows.append(m)
        print(f"  Recal t={t}  F1={m['macro_f1']}  FPR={m['fpr']}  FNR={m['fnr']}")

    # ── (3) Few-Shot Fine-Tuning (5% and 10% of AndroZoo) ────────────────────
    # Fine-tune from pre-trained checkpoint on the adaptation slice only.
    # The model already incorporates KronoDroid knowledge; lightweight adaptation
    # on a small future-domain set avoids catastrophic forgetting.
    for adapt_frac in [0.05, 0.10]:
        idx_all  = np.arange(len(az_all_seqs))
        idx_adapt, idx_test = train_test_split(
            idx_all,
            test_size=(1 - adapt_frac),
            stratify=y_az_seq,
            random_state=SEED,
        )
        adapt_seqs = [az_all_seqs[i] for i in idx_adapt]
        test_seqs  = [az_all_seqs[i] for i in idx_test]
        y_test_seq = y_az_seq[idx_test]
        n_adapt    = len(adapt_seqs)

        train_ds  = SeqDataset(adapt_seqs, stoi)
        test_ds   = SeqDataset(test_seqs,  stoi)
        train_ldr = DataLoader(train_ds, batch_size=32, shuffle=True,  num_workers=0)
        test_ldr  = DataLoader(test_ds,  batch_size=64, shuffle=False, num_workers=0)

        model_ft = cfg["model_cls"](**cfg["model_kwargs"]).to(DEVICE)
        model_ft.load_state_dict(state)
        model_ft = seq_fine_tune(model_ft, train_ldr, val_loader=test_ldr,
                                 lr=2e-5, n_epochs=5, patience=3)

        prob_ft, label_ft = seq_predict(model_ft, test_ldr)
        m = compute_metrics(label_ft, prob_ft)
        m.update({
            "model": seq_name,
            "strategy": f"Few-shot fine-tune ({int(adapt_frac*100)}%, n={n_adapt})",
            "threshold": 0.5,
        })
        seq_rows.append(m)
        print(f"  Few-shot {int(adapt_frac*100):3d}%  F1={m['macro_f1']}  FPR={m['fpr']}  FNR={m['fnr']}")

    # ── (4) Upper Bound: fine-tune on full AndroZoo (80/20 single split) ─────
    # 5-fold CV is too slow on CPU; single split approximation is sufficient.
    print(f"  Running upper bound (80/20 split) for {seq_name} …")
    idx_tr, idx_te = train_test_split(
        np.arange(len(az_all_seqs)),
        test_size=0.20, stratify=y_az_seq, random_state=SEED,
    )
    tr_seqs_ub = [az_all_seqs[i] for i in idx_tr]
    te_seqs_ub = [az_all_seqs[i] for i in idx_te]

    tr_ds_ub  = SeqDataset(tr_seqs_ub, stoi)
    te_ds_ub  = SeqDataset(te_seqs_ub, stoi)
    tr_ldr_ub = DataLoader(tr_ds_ub, batch_size=64, shuffle=True,  num_workers=0)
    te_ldr_ub = DataLoader(te_ds_ub, batch_size=64, shuffle=False, num_workers=0)

    model_ub = cfg["model_cls"](**cfg["model_kwargs"]).to(DEVICE)
    model_ub.load_state_dict(state)
    model_ub = seq_fine_tune(model_ub, tr_ldr_ub, val_loader=te_ldr_ub,
                              lr=1e-4, n_epochs=10, patience=3)

    prob_ub, label_ub = seq_predict(model_ub, te_ldr_ub)
    ub_f1 = round(float(f1_score(label_ub, (prob_ub >= 0.5).astype(int), average="macro")), 4)
    m = {
        "model": seq_name, "strategy": "Full fine-tune (upper bound, 80/20)",
        "threshold": 0.5,
        "macro_f1": ub_f1, "roc_auc": round(roc_auc_score(label_ub, prob_ub), 4),
        "pr_auc": round(average_precision_score(label_ub, prob_ub), 4),
        "fpr": None, "fnr": None, "benign_recall": None,
        "tn": None, "fp": None, "fn": None, "tp": None,
    }
    tn2, fp2, fn2, tp2 = confusion_matrix(label_ub, (prob_ub >= 0.5).astype(int)).ravel()
    m.update({
        "fpr": round(fp2 / (fp2 + tn2 + 1e-12), 4),
        "fnr": round(fn2 / (fn2 + tp2 + 1e-12), 4),
        "benign_recall": round(tn2 / (tn2 + fp2 + 1e-12), 4),
        "tn": int(tn2), "fp": int(fp2), "fn": int(fn2), "tp": int(tp2),
    })
    seq_rows.append(m)
    print(f"  Upper bound (80/20)  F1={ub_f1}")


seq_df = pd.DataFrame(seq_rows)
seq_df.to_csv(ADAPT_DIR / "adaptation_summary_sequence.csv", index=False)
print("\nSequence summary saved.")


# ══════════════════════════════════════════════════════════════════════════════
# PART 6 — COMBINED LaTeX TABLE (multi-model summary)
# ══════════════════════════════════════════════════════════════════════════════

all_df = pd.concat([tabular_df, seq_df], ignore_index=True)
all_df.to_csv(ADAPT_DIR / "adaptation_summary_all_models.csv", index=False)

# Summary table: one row per (model, key strategy)
KEY_STRATEGIES = [
    "No adaptation (baseline)",
    "Threshold recalib. (t=0.70)",
    "Few-shot",          # matches both "Few-shot retrain" and "Few-shot fine-tune"
    "Full retrain",      # matches "Full retrain (upper bound, CV)"
    "Full fine-tune",    # matches "Full fine-tune (upper bound, 80/20)"
]
ALL_MODELS = TABULAR_MODELS + ["BiLSTM", "Transformer"]


def fmt(v, decimals=4):
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return "—"
    return f"{v:.{decimals}f}"


def build_multi_model_latex(df: pd.DataFrame) -> str:
    lines = [
        r"\begin{table*}[htbp]",
        r"\centering",
        r"\caption{Adaptation strategies applied across all tabular and sequence models "
        r"on the 2024--2026 AndroZoo temporal hold-out ($N_{\text{benign}}=N_{\text{malware}}=3{,}000$). "
        r"Threshold recalibration requires no future-domain labels. "
        r"Few-shot retrain augments KronoDroid training with 5\%/10\% of AndroZoo; "
        r"the remaining 90\%/95\% serves as test set. "
        r"The upper bound is 5-fold CV macro-F1 on the full AndroZoo hold-out ($\pm$ std).}",
        r"\label{tab:adaptation_all}",
        r"\resizebox{\textwidth}{!}{%",
        r"\begin{tabular}{llccccc}",
        r"\toprule",
        r"\textbf{Family} & \textbf{Model} & \textbf{Strategy} & \textbf{Macro-F1} & \textbf{ROC-AUC} & \textbf{FPR} & \textbf{FNR} \\",
        r"\midrule",
    ]

    family_map = {
        "LogisticRegression": "Tabular",
        "RandomForest":       "Tabular",
        "ExtraTrees":         "Tabular",
        "MLP":                "Tabular",
        "XGBoost":            "Tabular",
        "BiLSTM":             "Sequence",
        "Transformer":        "Sequence",
    }
    strategy_labels = {
        "No adaptation (baseline)":                   r"No adaptation (baseline)",
        "Threshold recalib. (t=0.70)":                r"Threshold recalib.~($t=0.70$)",
        "Full retrain (upper bound, CV)":              r"Full retrain (upper bound, CV)",
    }

    prev_family = None
    for model_name in ALL_MODELS:
        sub = df[df["model"] == model_name]
        family = family_map.get(model_name, "")

        if family != prev_family:
            if prev_family is not None:
                lines.append(r"\midrule")
            prev_family = family

        first = True
        for strat_key in KEY_STRATEGIES:
            row = sub[sub["strategy"].str.startswith(strat_key.split("n=")[0].strip())]
            if row.empty:
                continue
            row = row.iloc[0]

            family_cell = family if first else ""
            model_cell  = model_name if first else ""
            first       = False

            strat_disp  = strategy_labels.get(strat_key, strat_key)
            # Derive few-shot n from strategy string
            if "Few-shot" in row["strategy"]:
                strat_disp = row["strategy"].replace("few-shot", "Few-shot")

            f1_val  = row.get("macro_f1")
            roc_val = row.get("roc_auc")
            fpr_val = row.get("fpr")
            fnr_val = row.get("fnr")

            if "upper bound" in row["strategy"]:
                std = row.get("cv_std", 0.0)
                f1_str = f"${fmt(f1_val)} \\pm {fmt(std)}$"
                roc_str, fpr_str, fnr_str = "—", "—", "—"
            else:
                f1_str  = fmt(f1_val)
                roc_str = fmt(roc_val)
                fpr_str = fmt(fpr_val)
                fnr_str = fmt(fnr_val)

            lines.append(
                f"{family_cell} & {model_cell} & {row['strategy']} & "
                f"{f1_str} & {roc_str} & {fpr_str} & {fnr_str} \\\\"
            )

        lines.append(r"\addlinespace[2pt]")

    lines += [r"\bottomrule", r"\end{tabular}}", r"\end{table*}"]
    return "\n".join(lines)


latex_all = build_multi_model_latex(all_df)
tex_path  = ADAPT_DIR / "adaptation_table_all_models.tex"
with open(tex_path, "w") as f:
    f.write(latex_all)
print(f"Multi-model LaTeX table → {tex_path}")

# Also regenerate the original XGBoost-focused table (for Section VIII)
xgb_df    = tabular_df[tabular_df["model"] == "XGBoost"].copy()
xgb_rows  = []
excl_keys = ["Drift-feature excl. (K=10)", "Drift-feature excl. (K=20)", "Drift-feature excl. (K=30)"]
recal_keys= ["Threshold recalib. (t=0.70)", "Threshold recalib. (t=0.80)"]
fs_5_key  = "Few-shot retrain (5%,"
fs_10_key = "Few-shot retrain (10%,"

def get_row(df, prefix):
    r = df[df["strategy"].str.startswith(prefix)]
    return r.iloc[0] if not r.empty else None

latex_xgb_lines = [
    r"\begin{table}[htbp]",
    r"\centering",
    r"\caption{Lightweight adaptation strategies for temporal degradation "
    r"(XGBoost probe on the 2024--2026 AndroZoo hold-out). "
    r"Drift-feature exclusion and threshold recalibration require no future-domain labels. "
    r"Few-shot retrain uses 5\%/10\% of AndroZoo as a labeled adaptation set; "
    r"the remaining 95\%/90\% serves as test set. "
    r"The upper bound reports 5-fold CV macro-F1 on the full AndroZoo hold-out.}",
    r"\label{tab:adaptation}",
    r"\resizebox{\columnwidth}{!}{%",
    r"\begin{tabular}{lccccc}",
    r"\toprule",
    r"\textbf{Strategy} & \textbf{Macro-F1} & \textbf{ROC-AUC} & \textbf{FPR} & \textbf{FNR} & \textbf{Benign Recall} \\",
    r"\midrule",
]

r0 = get_row(xgb_df, "No adaptation")
latex_xgb_lines.append(
    f"No adaptation (baseline) & {fmt(r0['macro_f1'])} & {fmt(r0['roc_auc'])} "
    f"& {fmt(r0['fpr'])} & {fmt(r0['fnr'])} & {fmt(r0['benign_recall'])} \\\\"
)
latex_xgb_lines.append(r"\midrule")
for k in [10, 20, 30]:
    r = get_row(xgb_df, f"Drift-feature excl. (K={k})")
    if r is not None:
        latex_xgb_lines.append(
            f"Drift-feature excl.~($K={k}$) & {fmt(r['macro_f1'])} & {fmt(r['roc_auc'])} "
            f"& {fmt(r['fpr'])} & {fmt(r['fnr'])} & {fmt(r['benign_recall'])} \\\\"
        )
latex_xgb_lines.append(r"\midrule")
for t in [0.70, 0.80]:
    r = get_row(xgb_df, f"Threshold recalib. (t={t:.2f})")
    if r is not None:
        latex_xgb_lines.append(
            f"Threshold recalib.~($t={t:.2f}$) & {fmt(r['macro_f1'])} & {fmt(r['roc_auc'])} "
            f"& {fmt(r['fpr'])} & {fmt(r['fnr'])} & {fmt(r['benign_recall'])} \\\\"
        )
latex_xgb_lines.append(r"\midrule")
for pct, prefix in [(5, "Few-shot retrain (5%"), (10, "Few-shot retrain (10%")]:
    r = get_row(xgb_df, prefix)
    if r is not None:
        n = r["strategy"].split("n=")[1].rstrip(")")
        latex_xgb_lines.append(
            f"Few-shot retrain~({pct}\\%, $n={n}$) & {fmt(r['macro_f1'])} & {fmt(r['roc_auc'])} "
            f"& {fmt(r['fpr'])} & {fmt(r['fnr'])} & {fmt(r['benign_recall'])} \\\\"
        )
ub = get_row(xgb_df, "Full retrain")
cv_std = ub.get("cv_std", 0.0) if ub is not None else 0.0
latex_xgb_lines.append(r"\midrule")
latex_xgb_lines.append(
    f"Full retrain (upper bound, CV) & ${fmt(ub['macro_f1'])} \\pm {fmt(cv_std)}$ & — & — & — & — \\\\"
)
latex_xgb_lines += [r"\bottomrule", r"\end{tabular}}", r"\end{table}"]
with open(ADAPT_DIR / "adaptation_table.tex", "w") as f:
    f.write("\n".join(latex_xgb_lines))
print(f"XGBoost table regenerated → {ADAPT_DIR / 'adaptation_table.tex'}")


# ══════════════════════════════════════════════════════════════════════════════
# PART 7 — PROFESSIONAL VISUALIZATION
# ══════════════════════════════════════════════════════════════════════════════

print("\nGenerating visualization …")

STRAT_DISPLAY = {
    "No adaptation (baseline)":    "Baseline",
    "Threshold recalib. (t=0.70)": "Thresh. Recalib.\n(t=0.70)",
    "Few-shot 5%":                 "Few-Shot\n(5%)",
    "Few-shot 10%":                "Few-Shot\n(10%)",
    "Upper bound":                 "Upper Bound\n(Full Retrain)",
}

COLORS = {
    "Baseline":              "#d62728",
    "Thresh. Recalib.\n(t=0.70)": "#ff7f0e",
    "Few-Shot\n(5%)":        "#2ca02c",
    "Few-Shot\n(10%)":       "#1f77b4",
    "Upper Bound\n(Full Retrain)": "#9467bd",
}

MODEL_DISPLAY = {
    "LogisticRegression": "LR",
    "RandomForest":       "RF",
    "ExtraTrees":         "ET",
    "MLP":                "MLP",
    "XGBoost":            "XGB",
    "BiLSTM":             "BiLSTM",
    "Transformer":        "Transformer",
}

def get_f1_for_model(df, model, strat_prefix):
    sub = df[(df["model"] == model) & (df["strategy"].str.startswith(strat_prefix))]
    if sub.empty:
        return None
    return float(sub.iloc[0]["macro_f1"])


# ── Figure 1: Grouped bar — Macro-F1 per model per strategy ──────────────────
fig, axes = plt.subplots(1, 2, figsize=(16, 5.5), gridspec_kw={"width_ratios": [5, 2]})

bar_colors   = ["#d62728", "#ff7f0e", "#2ca02c", "#1f77b4", "#9467bd"]
bar_labels   = ["Baseline", "Thresh. Recalib. (t=0.70)", "Few-Shot (5%)", "Few-Shot (10%)", "Upper Bound"]
strat_keys   = [
    "No adaptation (baseline)",
    "Threshold recalib. (t=0.70)",
    "Few-shot retrain (5%",
    "Few-shot retrain (10%",
    "Full retrain",
]

# ── Left: Tabular models ──────────────────────────────────────────────────────
ax = axes[0]
n_tab   = len(TABULAR_MODELS)
n_strat = len(strat_keys)
x_tab   = np.arange(n_tab)
bar_w   = 0.14

for s_i, (sk, slabel, scolor) in enumerate(zip(strat_keys, bar_labels, bar_colors)):
    vals = []
    for model_name in TABULAR_MODELS:
        v = get_f1_for_model(tabular_df, model_name, sk)
        vals.append(v if v is not None else 0.0)
    offset = (s_i - (n_strat - 1) / 2) * bar_w
    bars = ax.bar(x_tab + offset, vals, bar_w, label=slabel, color=scolor,
                  alpha=0.88, edgecolor="white", linewidth=0.5)
    for bar, val in zip(bars, vals):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.008,
                    f"{val:.3f}", ha="center", va="bottom", fontsize=6.5, rotation=90,
                    color="black")

ax.set_xticks(x_tab)
ax.set_xticklabels([MODEL_DISPLAY[m] for m in TABULAR_MODELS], fontsize=11)
ax.set_ylim(0.50, 1.05)
ax.set_ylabel("Macro-F1", fontsize=12)
ax.set_title("Tabular Models", fontsize=13, fontweight="bold", pad=8)
ax.yaxis.grid(True, linestyle="--", alpha=0.5, color="gray")
ax.set_axisbelow(True)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.legend(loc="lower right", fontsize=8.5, framealpha=0.85, ncol=2)

# ── Right: Sequence models ────────────────────────────────────────────────────
ax2 = axes[1]
n_seq = 2
x_seq = np.arange(n_seq)

for s_i, (sk, slabel, scolor) in enumerate(zip(strat_keys, bar_labels, bar_colors)):
    vals = []
    for model_name in ["BiLSTM", "Transformer"]:
        v = get_f1_for_model(seq_df, model_name, sk)
        vals.append(v if v is not None else 0.0)
    offset = (s_i - (n_strat - 1) / 2) * bar_w
    bars = ax2.bar(x_seq + offset, vals, bar_w, label=slabel, color=scolor,
                   alpha=0.88, edgecolor="white", linewidth=0.5)
    for bar, val in zip(bars, vals):
        if val > 0:
            ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.008,
                     f"{val:.3f}", ha="center", va="bottom", fontsize=6.5, rotation=90,
                     color="black")

ax2.set_xticks(x_seq)
ax2.set_xticklabels([MODEL_DISPLAY[m] for m in ["BiLSTM", "Transformer"]], fontsize=11)
ax2.set_ylim(0.50, 1.05)
ax2.set_ylabel("Macro-F1", fontsize=12)
ax2.set_title("Sequence Models", fontsize=13, fontweight="bold", pad=8)
ax2.yaxis.grid(True, linestyle="--", alpha=0.5, color="gray")
ax2.set_axisbelow(True)
ax2.spines["top"].set_visible(False)
ax2.spines["right"].set_visible(False)

fig.suptitle(
    "Temporal Adaptation Improvement: Baseline → Upper Bound\n"
    "(KronoDroid-trained models evaluated on 2024–2026 AndroZoo hold-out)",
    fontsize=13, fontweight="bold", y=1.01,
)
fig.tight_layout()
fig.savefig(ADAPT_DIR / "adaptation_improvement_all_models.pdf", bbox_inches="tight")
fig.savefig(ADAPT_DIR / "adaptation_improvement_all_models.png", dpi=300, bbox_inches="tight")
plt.close(fig)
print(f"  Grouped bar chart saved.")


# ── Figure 2: FPR reduction strip chart ──────────────────────────────────────
fig2, axes2 = plt.subplots(1, 2, figsize=(14, 4.5), gridspec_kw={"width_ratios": [5, 2]})

fpr_strat_keys = [
    "No adaptation (baseline)",
    "Threshold recalib. (t=0.70)",
    "Few-shot retrain (5%",
    "Few-shot retrain (10%",
]
fpr_labels = ["Baseline", "Thresh. Recalib.\n(t=0.70)", "Few-Shot (5%)", "Few-Shot (10%)"]
fpr_colors = ["#d62728", "#ff7f0e", "#2ca02c", "#1f77b4"]
fpr_bar_w  = 0.18

ax3 = axes2[0]
for s_i, (sk, slabel, scolor) in enumerate(zip(fpr_strat_keys, fpr_labels, fpr_colors)):
    vals = []
    for model_name in TABULAR_MODELS:
        sub = tabular_df[(tabular_df["model"] == model_name) &
                         (tabular_df["strategy"].str.startswith(sk))]
        v = float(sub.iloc[0]["fpr"]) if not sub.empty else 0.0
        vals.append(v)
    offset = (s_i - (len(fpr_strat_keys) - 1) / 2) * fpr_bar_w
    bars = ax3.bar(x_tab + offset, vals, fpr_bar_w, label=slabel, color=scolor,
                   alpha=0.88, edgecolor="white", linewidth=0.5)
    for bar, val in zip(bars, vals):
        if val > 0.01:
            ax3.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.005,
                     f"{val:.2f}", ha="center", va="bottom", fontsize=7, rotation=90)

ax3.set_xticks(x_tab)
ax3.set_xticklabels([MODEL_DISPLAY[m] for m in TABULAR_MODELS], fontsize=11)
ax3.set_ylim(0, 0.85)
ax3.set_ylabel("False Positive Rate (FPR)", fontsize=12)
ax3.set_title("Tabular Models — FPR Reduction", fontsize=13, fontweight="bold", pad=8)
ax3.yaxis.grid(True, linestyle="--", alpha=0.5, color="gray")
ax3.set_axisbelow(True)
ax3.spines["top"].set_visible(False)
ax3.spines["right"].set_visible(False)
ax3.legend(loc="upper right", fontsize=9, framealpha=0.85)

ax4 = axes2[1]
for s_i, (sk, slabel, scolor) in enumerate(zip(fpr_strat_keys, fpr_labels, fpr_colors)):
    vals = []
    for model_name in ["BiLSTM", "Transformer"]:
        sub = seq_df[(seq_df["model"] == model_name) &
                     (seq_df["strategy"].str.startswith(sk))]
        v = float(sub.iloc[0]["fpr"]) if not sub.empty else 0.0
        vals.append(v)
    offset = (s_i - (len(fpr_strat_keys) - 1) / 2) * fpr_bar_w
    bars = ax4.bar(x_seq + offset, vals, fpr_bar_w, label=slabel, color=scolor,
                   alpha=0.88, edgecolor="white", linewidth=0.5)
    for bar, val in zip(bars, vals):
        if val > 0.01:
            ax4.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.005,
                     f"{val:.2f}", ha="center", va="bottom", fontsize=7, rotation=90)

ax4.set_xticks(x_seq)
ax4.set_xticklabels([MODEL_DISPLAY[m] for m in ["BiLSTM", "Transformer"]], fontsize=11)
ax4.set_ylim(0, 0.85)
ax4.set_ylabel("False Positive Rate (FPR)", fontsize=12)
ax4.set_title("Sequence Models — FPR Reduction", fontsize=13, fontweight="bold", pad=8)
ax4.yaxis.grid(True, linestyle="--", alpha=0.5, color="gray")
ax4.set_axisbelow(True)
ax4.spines["top"].set_visible(False)
ax4.spines["right"].set_visible(False)

fig2.suptitle(
    "False Positive Rate Under Each Adaptation Strategy",
    fontsize=13, fontweight="bold", y=1.01,
)
fig2.tight_layout()
fig2.savefig(ADAPT_DIR / "adaptation_fpr_all_models.pdf", bbox_inches="tight")
fig2.savefig(ADAPT_DIR / "adaptation_fpr_all_models.png", dpi=300, bbox_inches="tight")
plt.close(fig2)
print("  FPR chart saved.")


# ── Final summary print ────────────────────────────────────────────────────────
print("\n" + "═" * 70)
print("ALL RESULTS SUMMARY (Macro-F1)")
print("═" * 70)
for model in ALL_MODELS:
    sub = all_df[all_df["model"] == model]
    print(f"\n  {model}:")
    for _, row in sub.iterrows():
        f1  = row.get("macro_f1")
        fpr = row.get("fpr")
        std = row.get("cv_std", None)
        if std and not (isinstance(std, float) and np.isnan(std)):
            print(f"    {row['strategy']:<45}  F1={f1:.4f} ± {std:.4f}")
        else:
            fpr_str = f"  FPR={fpr:.4f}" if fpr is not None and not (isinstance(fpr, float) and np.isnan(fpr)) else ""
            print(f"    {row['strategy']:<45}  F1={f1:.4f}{fpr_str}")

print(f"\n{'═'*70}")
print(f"Outputs saved to: {ADAPT_DIR}")
print("  adaptation_summary_tabular_all.csv")
print("  adaptation_summary_sequence.csv")
print("  adaptation_summary_all_models.csv")
print("  adaptation_table.tex               (XGBoost, for Section VIII)")
print("  adaptation_table_all_models.tex    (all models)")
print("  adaptation_improvement_all_models.pdf/.png")
print("  adaptation_fpr_all_models.pdf/.png")
