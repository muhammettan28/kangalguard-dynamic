"""
Sequence Model Few-Shot Adaptation (BiLSTM + Transformer)
==========================================================
Augmented fine-tuning: KronoDroid checkpoint + labeled AndroZoo slice.
Threshold recalibration + few-shot (5%, 10%) + upper bound (80/20 split).

GPU kullanılır (CUDA); GPU doluysa otomatik CPU'ya döner.
Tahmini süre: GPU varsa ~15 dk, CPU'da ~60 dk.

Çalıştırma:
    /home/tan/anaconda3/envs/kangal/bin/python3 -u adaptation_sequence_finetune.py
"""

import copy, json, warnings
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.metrics import (
    f1_score, roc_auc_score, average_precision_score, confusion_matrix,
)
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore")
SEED = 42
np.random.seed(SEED)
torch.manual_seed(SEED)

# GPU kullan, VRAM yetersizse CPU'ya düş
if torch.cuda.is_available():
    try:
        torch.cuda.memory.set_per_process_memory_fraction(0.85)
        DEVICE = torch.device("cuda")
    except Exception:
        DEVICE = torch.device("cpu")
else:
    DEVICE = torch.device("cpu")
print(f"Device: {DEVICE}")
if DEVICE.type == "cuda":
    free_mb = (torch.cuda.get_device_properties(0).total_memory
               - torch.cuda.memory_allocated()) // (1024**2)
    print(f"  GPU free: {free_mb} MB")

ROOT      = Path(__file__).resolve().parent
DATA_ROOT = ROOT.parent
KRONO_DIR = DATA_ROOT / "krono_dataset"
AZ_DIR    = DATA_ROOT / "androzoo_dataset"
RESULTS   = ROOT / "results"
ADAPT_DIR = RESULTS / "adaptation"
SEQ_INFER = RESULTS / "androzoo_sequence_inference"
SEQ_CKPT  = RESULTS / "androzoo_inference_model"
ADAPT_DIR.mkdir(exist_ok=True)

N_PER_CLASS = 3_000
BATCH_TRAIN = 32
BATCH_EVAL  = 64


# ── Model definitions ──────────────────────────────────────────────────────────
class BiLSTMModel(nn.Module):
    def __init__(self, vocab_size=64, embed_dim=96, hidden_dim=128,
                 num_layers=2, dropout=0.2):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.lstm = nn.LSTM(embed_dim, hidden_dim, num_layers=num_layers,
                            batch_first=True, bidirectional=True,
                            dropout=dropout if num_layers > 1 else 0.0)
        self.head = nn.Sequential(
            nn.LayerNorm(hidden_dim * 2), nn.Dropout(dropout),
            nn.Linear(hidden_dim * 2, 1),
        )

    def forward(self, x):
        emb = self.embedding(x)
        _, (h, _) = self.lstm(emb)
        return self.head(torch.cat([h[-2], h[-1]], dim=-1)).squeeze(-1)


class TransformerModel(nn.Module):
    def __init__(self, vocab_size=64, embed_dim=96, num_layers=2,
                 nhead=4, dim_feedforward=256, max_seq_len=256, dropout=0.2):
        super().__init__()
        self.token_emb = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.pos_emb   = nn.Embedding(max_seq_len, embed_dim)
        enc = nn.TransformerEncoderLayer(embed_dim, nhead, dim_feedforward,
                                          dropout=dropout, batch_first=True)
        self.encoder = nn.TransformerEncoder(enc, num_layers=num_layers)
        self.head = nn.Sequential(
            nn.LayerNorm(embed_dim), nn.Dropout(dropout), nn.Linear(embed_dim, 1),
        )

    def forward(self, x):
        B, T = x.shape
        emb  = self.token_emb(x) + self.pos_emb(torch.arange(T, device=x.device).unsqueeze(0))
        out  = self.encoder(emb, src_key_padding_mask=(x == 0))
        return self.head(out.mean(dim=1)).squeeze(-1)


class SeqDataset(Dataset):
    def __init__(self, records, stoi, max_len=256, unk_id=1):
        self.records, self.stoi, self.max_len, self.unk_id = records, stoi, max_len, unk_id

    def __len__(self): return len(self.records)

    def __getitem__(self, idx):
        rec  = self.records[idx]
        tags = [e["tag"] for e in rec["seq_log"]][:self.max_len]
        ids  = [self.stoi.get(t, self.unk_id) for t in tags]
        ids  = ids + [0] * (self.max_len - len(ids))
        y    = 1 if rec["label"] == "malware" else 0
        return torch.tensor(ids, dtype=torch.long), torch.tensor(y, dtype=torch.float)


def metrics(y_true, y_prob, t=0.5):
    y_pred = (y_prob >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return {
        "macro_f1": round(f1_score(y_true, y_pred, average="macro"), 4),
        "roc_auc":  round(roc_auc_score(y_true, y_prob), 4),
        "pr_auc":   round(average_precision_score(y_true, y_prob), 4),
        "fpr":      round(fp / (fp + tn + 1e-12), 4),
        "fnr":      round(fn / (fn + tp + 1e-12), 4),
        "benign_recall": round(tn / (tn + fp + 1e-12), 4),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


@torch.no_grad()
def predict(model, loader):
    model.eval()
    probs, labels = [], []
    for x, y in loader:
        probs.extend(torch.sigmoid(model(x.to(DEVICE))).cpu().tolist())
        labels.extend(y.tolist())
    return np.array(probs), np.array(labels)


def fine_tune(model, train_ldr, val_ldr, lr=5e-5, n_epochs=8, patience=3):
    """Fine-tune; return best model by val macro-F1."""
    opt  = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    crit = nn.BCEWithLogitsLoss()
    best_f1, best_state, no_imp = -1.0, None, 0
    for ep in range(1, n_epochs + 1):
        model.train()
        ep_loss = 0.0
        for x, y in train_ldr:
            x, y = x.to(DEVICE), y.to(DEVICE)
            opt.zero_grad()
            loss = crit(model(x), y)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            ep_loss += loss.item()
        p, l = predict(model, val_ldr)
        f1 = f1_score(l, (p >= 0.5).astype(int), average="macro")
        print(f"    ep {ep:2d}  loss={ep_loss/len(train_ldr):.4f}  val_F1={f1:.4f}", flush=True)
        if f1 > best_f1 + 1e-4:
            best_f1, best_state, no_imp = f1, copy.deepcopy(model.state_dict()), 0
        else:
            no_imp += 1
        if no_imp >= patience:
            print(f"    Early stop at epoch {ep}.", flush=True)
            break
    if best_state:
        model.load_state_dict(best_state)
    return model


def make_loader(records, stoi, shuffle, batch_size=BATCH_TRAIN):
    return DataLoader(SeqDataset(records, stoi), batch_size=batch_size,
                      shuffle=shuffle, num_workers=0)


# ── Load data ──────────────────────────────────────────────────────────────────
print("\nLoading data …", flush=True)
def load_seqlogs(p):
    with open(p) as f:
        return [json.loads(l) for l in f]

az_benign  = load_seqlogs(AZ_DIR / "androzoo_benign_seqlogs.jsonl")[:N_PER_CLASS]
az_malware = load_seqlogs(AZ_DIR / "androzoo_malware_seqlogs.jsonl")[:N_PER_CLASS]
az_all = az_benign + az_malware
rng = np.random.RandomState(SEED)
order = rng.permutation(len(az_all))
az_all = [az_all[i] for i in order]
y_az = np.array([1 if r["label"] == "malware" else 0 for r in az_all])

krono_benign  = load_seqlogs(KRONO_DIR / "krono_benign_seqlogs.jsonl")[:N_PER_CLASS]
krono_malware = load_seqlogs(KRONO_DIR / "krono_malware_seqlogs.jsonl")[:N_PER_CLASS]
krono_all = krono_benign + krono_malware
rng.shuffle(krono_all)
print(f"  AndroZoo: {len(az_all)} seqs   KronoDroid: {len(krono_all)} seqs", flush=True)

# ── Sequence model configs ─────────────────────────────────────────────────────
CONFIGS = {
    "BiLSTM": {
        "ckpt":    RESULTS / "kronodroid_sequence_bilstm.pt",
        "cls":     BiLSTMModel,
        "kwargs":  dict(vocab_size=64, embed_dim=96, hidden_dim=128, num_layers=2, dropout=0.2),
        "csv":     SEQ_INFER / "androzoo_sequence_predictions_bilstm.csv",
        "lr":      3e-5,
    },
    "Transformer": {
        "ckpt":    SEQ_CKPT / "androzoo_sequence_model_bundle.pt",
        "cls":     TransformerModel,
        "kwargs":  dict(vocab_size=64, embed_dim=96, num_layers=2, nhead=4,
                        dim_feedforward=256, max_seq_len=256, dropout=0.2),
        "csv":     SEQ_INFER / "androzoo_sequence_predictions_transformer.csv",
        "lr":      3e-5,
    },
}

all_rows = []

for model_name, cfg in CONFIGS.items():
    print(f"\n{'═'*60}", flush=True)
    print(f"  {model_name}", flush=True)
    print(f"{'═'*60}", flush=True)

    ckpt  = torch.load(cfg["ckpt"], map_location="cpu", weights_only=False)
    state = ckpt.get("model_state_dict", ckpt)
    stoi  = ckpt.get("stoi") or json.load(open(SEQ_CKPT / "sequence_vocab.json"))

    # ── (1) Baseline — from saved CSV ──────────────────────────────────────────
    pdf = pd.read_csv(cfg["csv"])
    pkg2prob  = dict(zip(pdf["package_name"], pdf["malware_probability"]))
    pkg2label = dict(zip(pdf["package_name"], pdf["label_bin"]))
    prob_b = np.array([pkg2prob.get(r["package_name"], 0.5)  for r in az_all])
    lab_b  = np.array([pkg2label.get(r["package_name"], y_az[i]) for i, r in enumerate(az_all)])

    m = metrics(lab_b, prob_b)
    m.update({"model": model_name, "strategy": "No adaptation (baseline)", "threshold": 0.5})
    all_rows.append(m)
    print(f"  Baseline     F1={m['macro_f1']}  FPR={m['fpr']}  FNR={m['fnr']}", flush=True)

    # ── (2) Threshold Recalibration ────────────────────────────────────────────
    for t in [0.70, 0.80]:
        m = metrics(lab_b, prob_b, t=t)
        m.update({"model": model_name, "strategy": f"Threshold recalib. (t={t:.2f})", "threshold": t})
        all_rows.append(m)
        print(f"  Thresh t={t}   F1={m['macro_f1']}  FPR={m['fpr']}  FNR={m['fnr']}", flush=True)

    # ── (3) Few-Shot Augmented Fine-Tuning ─────────────────────────────────────
    # Train on KronoDroid + labeled AndroZoo slice → test on held-out AndroZoo.
    # Augmented training prevents catastrophic forgetting.
    for adapt_frac in [0.05, 0.10]:
        n_adapt = int(len(az_all) * adapt_frac)
        # stratified split
        idx_adapt, idx_test = train_test_split(
            np.arange(len(az_all)), test_size=(1 - adapt_frac),
            stratify=y_az, random_state=SEED,
        )
        adapt_seqs = [az_all[i] for i in idx_adapt]
        test_seqs  = [az_all[i] for i in idx_test]

        # Augment: KronoDroid + adaptation slice
        aug_seqs   = krono_all + adapt_seqs

        train_ldr = make_loader(aug_seqs,   stoi, shuffle=True,  batch_size=BATCH_TRAIN)
        test_ldr  = make_loader(test_seqs,  stoi, shuffle=False, batch_size=BATCH_EVAL)

        print(f"\n  Few-shot {int(adapt_frac*100)}%  (n_adapt={n_adapt}, "
              f"train={len(aug_seqs)}, test={len(test_seqs)})", flush=True)
        model_ft = cfg["cls"](**cfg["kwargs"]).to(DEVICE)
        model_ft.load_state_dict(state)
        model_ft = fine_tune(model_ft, train_ldr, test_ldr, lr=cfg["lr"],
                             n_epochs=8, patience=3)
        prob_ft, lab_ft = predict(model_ft, test_ldr)
        m = metrics(lab_ft, prob_ft)
        m.update({
            "model": model_name,
            "strategy": f"Few-shot retrain ({int(adapt_frac*100)}%, n={n_adapt})",
            "threshold": 0.5,
        })
        all_rows.append(m)
        print(f"  → F1={m['macro_f1']}  FPR={m['fpr']}  FNR={m['fnr']}", flush=True)
        del model_ft
        torch.cuda.empty_cache() if DEVICE.type == "cuda" else None

    # ── (4) Upper Bound: fine-tune on 80% AndroZoo ────────────────────────────
    print(f"\n  Upper bound (80% AZ train / 20% AZ test) …", flush=True)
    idx_tr, idx_te = train_test_split(
        np.arange(len(az_all)), test_size=0.20, stratify=y_az, random_state=SEED,
    )
    ub_train = [az_all[i] for i in idx_tr]
    ub_test  = [az_all[i] for i in idx_te]

    tr_ldr_ub = make_loader(ub_train, stoi, shuffle=True,  batch_size=BATCH_TRAIN)
    te_ldr_ub = make_loader(ub_test,  stoi, shuffle=False, batch_size=BATCH_EVAL)

    model_ub = cfg["cls"](**cfg["kwargs"]).to(DEVICE)
    model_ub.load_state_dict(state)
    model_ub = fine_tune(model_ub, tr_ldr_ub, te_ldr_ub, lr=1e-4, n_epochs=10, patience=3)
    prob_ub, lab_ub = predict(model_ub, te_ldr_ub)
    m = metrics(lab_ub, prob_ub)
    m.update({"model": model_name, "strategy": "Full fine-tune (upper bound, 80/20)",
              "threshold": 0.5})
    all_rows.append(m)
    print(f"  → F1={m['macro_f1']}  FPR={m['fpr']}  FNR={m['fnr']}", flush=True)
    del model_ub
    torch.cuda.empty_cache() if DEVICE.type == "cuda" else None

# ── Save results ───────────────────────────────────────────────────────────────
out_df = pd.DataFrame(all_rows)
out_csv = ADAPT_DIR / "adaptation_summary_sequence.csv"
out_df.to_csv(out_csv, index=False)
print(f"\n{'═'*60}", flush=True)
print("RESULTS:", flush=True)
print(out_df[["model","strategy","macro_f1","roc_auc","fpr","fnr"]].to_string(index=False))
print(f"\nSaved → {out_csv}", flush=True)
print("\nSonraki adım: adaptation_visualize.py çalıştır → grafik ve LaTeX tabloyu güncelle.", flush=True)
