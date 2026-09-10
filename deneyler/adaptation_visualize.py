"""
Adaptation Results Visualization
=================================
Generates professional grouped bar charts from adaptation summary CSVs.
Run after adaptation_sequence_only.py completes.

Usage:
    /home/tan/anaconda3/envs/kangal/bin/python3 adaptation_visualize.py
"""

from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ADAPT_DIR = Path(__file__).resolve().parent / "results" / "adaptation"
OUT_DIR   = ADAPT_DIR

# ── Load data ─────────────────────────────────────────────────────────────────
tab_df = pd.read_csv(ADAPT_DIR / "adaptation_summary_tabular_all.csv")
seq_df = pd.read_csv(ADAPT_DIR / "adaptation_summary_sequence.csv")

TABULAR_MODELS  = ["LogisticRegression", "RandomForest", "ExtraTrees", "MLP", "XGBoost"]
SEQUENCE_MODELS = ["BiLSTM", "Transformer"]

MODEL_SHORT = {
    "LogisticRegression": "LR",
    "RandomForest":       "RF",
    "ExtraTrees":         "ET",
    "MLP":                "MLP",
    "XGBoost":            "XGB",
    "BiLSTM":             "BiLSTM",
    "Transformer":        "Transf.",
}

# Strategy → (label, color, priority)
STRAT_MAP = [
    ("No adaptation (baseline)",          "Baseline",          "#d62728", 0),
    ("Threshold recalib. (t=0.70)",       "Thresh. (t=0.70)",  "#ff7f0e", 1),
    ("Few-shot retrain (5%",              "Few-Shot 5%",       "#2ca02c", 2),
    ("Few-shot fine-tune (5%",            "Few-Shot 5%",       "#2ca02c", 2),
    ("Few-shot retrain (10%",             "Few-Shot 10%",      "#1f77b4", 3),
    ("Few-shot fine-tune (10%",           "Few-Shot 10%",      "#1f77b4", 3),
    ("Full retrain (upper bound, CV)",    "Upper Bound",       "#9467bd", 4),
    ("Full fine-tune (upper bound, 80/20)", "Upper Bound",     "#9467bd", 4),
]

def find_metric(df, model, strat_prefix, metric="macro_f1"):
    sub = df[(df["model"] == model) & (df["strategy"].str.startswith(strat_prefix))]
    if sub.empty:
        return None
    v = sub.iloc[0][metric]
    return None if (v is None or (isinstance(v, float) and np.isnan(v))) else float(v)


def get_row(df, model, strat_prefix):
    sub = df[(df["model"] == model) & (df["strategy"].str.startswith(strat_prefix))]
    return sub.iloc[0] if not sub.empty else None


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 1 — Macro-F1 improvement grouped bar chart
# ══════════════════════════════════════════════════════════════════════════════

# We show 4 bars per model: Baseline / Thresh(t=0.70) / Few-Shot 5% / Upper Bound
# (Few-Shot 10% makes the chart crowded; it's in the table)
PLOT_STRATS = [
    ("No adaptation (baseline)",   "Baseline",         "#d62728"),
    ("Threshold recalib. (t=0.70)", "Thresh. (t=0.70)", "#ff7f0e"),
    ("Few-shot",                   "Few-Shot (5%+10%)", "#2ca02c"),
    ("Full",                       "Upper Bound",      "#9467bd"),
]

# For "Few-Shot" we take the 10% version (better performance)
# For "Full" we take whichever is present

def get_f1(df, model, prefix):
    # For few-shot: prefer 10%
    sub10 = df[(df["model"]==model) & (df["strategy"].str.contains("10%")) &
               (df["strategy"].str.startswith(prefix))]
    if not sub10.empty:
        return float(sub10.iloc[0]["macro_f1"])
    sub = df[(df["model"]==model) & (df["strategy"].str.startswith(prefix))]
    if sub.empty:
        return None
    v = sub.iloc[0]["macro_f1"]
    return None if (v is None or (isinstance(v, float) and np.isnan(v))) else float(v)


fig, axes = plt.subplots(1, 2, figsize=(15, 5.5),
                         gridspec_kw={"width_ratios": [5, 2]})
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10})

bar_w    = 0.18
n_strats = len(PLOT_STRATS)

for ax, models, df_src, title in [
    (axes[0], TABULAR_MODELS,  tab_df, "Tabular Models"),
    (axes[1], SEQUENCE_MODELS, seq_df, "Sequence Models"),
]:
    x     = np.arange(len(models))
    for s_i, (sk, slabel, scolor) in enumerate(PLOT_STRATS):
        vals = [get_f1(df_src, m, sk) for m in models]
        offset = (s_i - (n_strats - 1) / 2) * bar_w
        bars = ax.bar(x + offset, [v if v else 0 for v in vals],
                      bar_w, label=slabel, color=scolor,
                      alpha=0.88, edgecolor="white", linewidth=0.6)
        for bar, val in zip(bars, vals):
            if val and val > 0.01:
                ax.text(bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + 0.007,
                        f"{val:.3f}", ha="center", va="bottom",
                        fontsize=6.2, rotation=88, color="#333333")

    ax.set_xticks(x)
    ax.set_xticklabels([MODEL_SHORT[m] for m in models], fontsize=11)
    ax.set_ylim(0.48, 1.06)
    ax.set_ylabel("Macro-F1", fontsize=11)
    ax.set_title(title, fontsize=12, fontweight="bold", pad=7)
    ax.yaxis.grid(True, linestyle="--", alpha=0.45, color="gray")
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.axhline(y=0.5, color="gray", linestyle=":", linewidth=0.8, alpha=0.6)

# Shared legend under both panels
handles = [plt.Rectangle((0,0),1,1, color=c, alpha=0.88) for _, l, c in PLOT_STRATS]
labels  = [l for _, l, c in PLOT_STRATS]
fig.legend(handles, labels, loc="lower center", ncol=4, fontsize=10,
           bbox_to_anchor=(0.5, -0.05), framealpha=0.9,
           edgecolor="#cccccc")

fig.suptitle(
    "Temporal Adaptation: Macro-F1 per Model and Strategy\n"
    "(KronoDroid-trained probes evaluated on 2024–2026 AndroZoo hold-out)",
    fontsize=12, fontweight="bold", y=1.02,
)
fig.tight_layout(rect=[0, 0.06, 1, 1])
fig.savefig(OUT_DIR / "adaptation_f1_all_models.pdf", bbox_inches="tight")
fig.savefig(OUT_DIR / "adaptation_f1_all_models.png", dpi=300, bbox_inches="tight")
plt.close(fig)
print("F1 chart saved.")


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 2 — FPR reduction chart (same structure)
# ══════════════════════════════════════════════════════════════════════════════

FPR_PLOT_STRATS = [
    ("No adaptation (baseline)",    "Baseline",         "#d62728"),
    ("Threshold recalib. (t=0.70)", "Thresh. (t=0.70)", "#ff7f0e"),
    ("Few-shot",                    "Few-Shot (10%)",    "#2ca02c"),
]

def get_fpr(df, model, prefix):
    sub10 = df[(df["model"]==model) & (df["strategy"].str.contains("10%")) &
               (df["strategy"].str.startswith(prefix))]
    if not sub10.empty:
        v = sub10.iloc[0]["fpr"]
        return None if (v is None or (isinstance(v, float) and np.isnan(v))) else float(v)
    sub = df[(df["model"]==model) & (df["strategy"].str.startswith(prefix))]
    if sub.empty:
        return None
    v = sub.iloc[0]["fpr"]
    return None if (v is None or (isinstance(v, float) and np.isnan(v))) else float(v)


fig2, axes2 = plt.subplots(1, 2, figsize=(13, 4.8),
                            gridspec_kw={"width_ratios": [5, 2]})
bar_w2 = 0.22

for ax, models, df_src, title in [
    (axes2[0], TABULAR_MODELS,  tab_df, "Tabular Models — FPR"),
    (axes2[1], SEQUENCE_MODELS, seq_df, "Sequence Models — FPR"),
]:
    x = np.arange(len(models))
    for s_i, (sk, slabel, scolor) in enumerate(FPR_PLOT_STRATS):
        vals = [get_fpr(df_src, m, sk) for m in models]
        offset = (s_i - (len(FPR_PLOT_STRATS) - 1) / 2) * bar_w2
        bars = ax.bar(x + offset, [v if v else 0 for v in vals],
                      bar_w2, label=slabel, color=scolor,
                      alpha=0.88, edgecolor="white", linewidth=0.6)
        for bar, val in zip(bars, vals):
            if val and val > 0.005:
                ax.text(bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + 0.005,
                        f"{val:.2f}", ha="center", va="bottom",
                        fontsize=7.5, color="#333333")

    ax.set_xticks(x)
    ax.set_xticklabels([MODEL_SHORT[m] for m in models], fontsize=11)
    ax.set_ylim(0, 0.80)
    ax.set_ylabel("False Positive Rate (FPR)", fontsize=11)
    ax.set_title(title, fontsize=12, fontweight="bold", pad=7)
    ax.yaxis.grid(True, linestyle="--", alpha=0.45, color="gray")
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

handles2 = [plt.Rectangle((0,0),1,1, color=c, alpha=0.88) for _, l, c in FPR_PLOT_STRATS]
labels2  = [l for _, l, c in FPR_PLOT_STRATS]
fig2.legend(handles2, labels2, loc="lower center", ncol=3, fontsize=10,
            bbox_to_anchor=(0.5, -0.05), framealpha=0.9, edgecolor="#cccccc")

fig2.suptitle(
    "False Positive Rate Reduction per Adaptation Strategy",
    fontsize=12, fontweight="bold", y=1.01,
)
fig2.tight_layout(rect=[0, 0.06, 1, 1])
fig2.savefig(OUT_DIR / "adaptation_fpr_all_models.pdf", bbox_inches="tight")
fig2.savefig(OUT_DIR / "adaptation_fpr_all_models.png", dpi=300, bbox_inches="tight")
plt.close(fig2)
print("FPR chart saved.")


# ══════════════════════════════════════════════════════════════════════════════
# LaTeX table — multi-model summary (key strategies only)
# ══════════════════════════════════════════════════════════════════════════════

def fmt(v, d=4):
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return "—"
    return f"{v:.{d}f}"


def build_latex_summary(tab_df, seq_df):
    all_df = pd.concat([tab_df, seq_df], ignore_index=True)

    # strategies to display per model
    DISPLAY = [
        ("No adaptation (baseline)",        "No adaptation (baseline)"),
        ("Threshold recalib. (t=0.70)",     r"Threshold recalib.~($t=0.70$)"),
        ("Few-shot retrain (5%",            r"Few-shot retrain (5\%, $n=300$)"),
        ("Few-shot fine-tune (5%",          r"Few-shot fine-tune (5\%, $n=300$)"),
        ("Few-shot retrain (10%",           r"Few-shot retrain (10\%, $n=600$)"),
        ("Few-shot fine-tune (10%",         r"Few-shot fine-tune (10\%, $n=600$)"),
        ("Full retrain (upper bound, CV)",  r"Full retrain (upper bound, CV)"),
        ("Full fine-tune (upper bound",     r"Full fine-tune (upper bound, 80/20)"),
    ]

    FAMILY = {m: "Tabular" for m in TABULAR_MODELS}
    FAMILY.update({"BiLSTM": "Sequence", "Transformer": "Sequence"})
    ALL_MODELS = TABULAR_MODELS + SEQUENCE_MODELS

    lines = [
        r"\begin{table*}[htbp]",
        r"\centering",
        (r"\caption{Adaptation strategies across all tabular and sequence models "
         r"on the 2024--2026 AndroZoo temporal hold-out "
         r"($N_{\text{benign}}=N_{\text{malware}}=3{,}000$). "
         r"Threshold recalibration requires no future-domain labels. "
         r"Few-shot retrain/fine-tune augments/adapts from the KronoDroid checkpoint with "
         r"5\%/10\% of AndroZoo; the remaining 95\%/90\% serves as test set. "
         r"Sequence upper bound uses an 80/20 single split; "
         r"tabular upper bound uses 5-fold CV ($\pm$std).}"),
        r"\label{tab:adaptation_all}",
        r"\resizebox{\textwidth}{!}{%",
        r"\begin{tabular}{lllccccc}",
        r"\toprule",
        (r"\textbf{Family} & \textbf{Model} & \textbf{Strategy} & "
         r"\textbf{Macro-F1} & \textbf{ROC-AUC} & \textbf{FPR} & "
         r"\textbf{FNR} & \textbf{Benign Rec.} \\"),
        r"\midrule",
    ]

    prev_family = None
    for model in ALL_MODELS:
        family = FAMILY[model]
        sub = all_df[all_df["model"] == model]
        if family != prev_family and prev_family is not None:
            lines.append(r"\midrule")
        prev_family = family
        first = True
        for strat_prefix, strat_disp in DISPLAY:
            row_match = sub[sub["strategy"].str.startswith(strat_prefix)]
            if row_match.empty:
                continue
            row = row_match.iloc[0]
            fam_cell   = family if first else ""
            model_cell = MODEL_SHORT[model] if first else ""
            first      = False

            f1  = row.get("macro_f1")
            roc = row.get("roc_auc")
            fpr = row.get("fpr")
            fnr = row.get("fnr")
            br  = row.get("benign_recall")
            std = row.get("cv_std") if hasattr(row, "get") else None

            if f1 is not None and not np.isnan(float(f1)) and std is not None and not np.isnan(float(std)):
                f1_str = f"${fmt(f1)} \\pm {fmt(std)}$"
            else:
                f1_str = fmt(f1)

            lines.append(
                f"{fam_cell} & {model_cell} & {strat_disp} & "
                f"{f1_str} & {fmt(roc)} & {fmt(fpr)} & {fmt(fnr)} & {fmt(br)} \\\\"
            )
        lines.append(r"\addlinespace[1.5pt]")

    lines += [r"\bottomrule", r"\end{tabular}}", r"\end{table*}"]
    return "\n".join(lines)


latex_str = build_latex_summary(tab_df, seq_df)
tex_path  = ADAPT_DIR / "adaptation_table_all_models.tex"
with open(tex_path, "w") as f:
    f.write(latex_str)
print(f"Multi-model LaTeX table → {tex_path}")

print("\nDone. All artifacts saved to:", ADAPT_DIR)
