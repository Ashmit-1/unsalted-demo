"""
Six publication-quality comparison graphs — four-way (unsalted / salted / stretched / peppered).
"""

import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# Palette — monochrome + one accent
BLACK  = "#000000"
DARK   = "#0d0d0d"
WHITE  = "#ffffff"
GREEN  = "#00ff41"
RED    = "#ef4444"
AMBER  = "#f59e0b"
BLUE   = "#60a5fa"
PURPLE = "#a78bfa"
DIM    = "#555555"

SYSTEMS = ["Unsalted", "Salted", "Stretched", "Peppered"]
COLS    = [RED, BLUE, AMBER, GREEN]
MARKS   = ['X', 'o', 's', 'D']

plt.rcParams.update({
    "figure.facecolor":  BLACK,
    "axes.facecolor":    DARK,
    "axes.edgecolor":    WHITE,
    "axes.labelcolor":   WHITE,
    "xtick.color":       WHITE,
    "ytick.color":       WHITE,
    "text.color":        WHITE,
    "grid.color":        "#222222",
    "grid.alpha":        0.5,
    "axes.grid":         True,
    "axes.spines.top":   False,
    "axes.spines.right": False,
    "font.family":       "monospace",
    "font.size":         10,
    "legend.facecolor":  DARK,
    "legend.edgecolor":  DIM,
    "legend.labelcolor": WHITE,
})


# ── Graph 1: Four-way Success Rate ───────────────────────────────────────────
def plot_success_rate(r: dict) -> plt.Figure:
    fig, ax = plt.subplots(figsize=(12, 6), facecolor=BLACK)
    ax.set_facecolor(DARK)
    keys = ["unsalted", "salted", "stretched", "peppered"]

    for key, col, mk, label in zip(keys, COLS, MARKS, SYSTEMS):
        ids = [x["test_id"]      for x in r[key]]
        srs = [x["success_rate"] for x in r[key]]
        ax.plot(ids, srs, color=col, marker=mk, linewidth=1.8,
                markersize=5, label=label, alpha=0.9)
        ax.fill_between(ids, srs, alpha=0.06, color=col)

    ax.axhline(90, color=WHITE, linestyle='--', linewidth=0.8, alpha=0.4,
               label="90% threshold")
    ax.set_xlabel("Test Case  ID")
    ax.set_ylabel("Attack Success Rate  (%)")
    ax.set_title("GRAPH 1 — Attack Success Rate: All Four Systems",
                 color=WHITE, fontweight='bold', pad=14, fontsize=12)
    ax.set_ylim(-5, 110)
    ax.legend(framealpha=0.3)
    fig.tight_layout()
    return fig


# ── Graph 2: Work formula validation — Time vs |D| ───────────────────────────
def plot_work_validation(r: dict) -> plt.Figure:
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 6), facecolor=BLACK)
    for ax in (ax1, ax2):
        ax.set_facecolor(DARK)

    u = r["unsalted"]
    sizes = np.array([x["dict_size"]        for x in u])
    pre_t = np.array([x["precompute_time"]  for x in u])
    pred  = np.array([x["predicted_W"]      for x in u])

    ax1.scatter(sizes, pre_t, color=RED,   s=55, alpha=0.8, label="actual precompute")
    ax1.scatter(sizes, pred,  color=GREEN, s=55, alpha=0.8, marker='^', label="predicted W=|D|·T_h")
    z = np.polyfit(sizes, pre_t, 1)
    xs = np.linspace(sizes.min(), sizes.max(), 200)
    ax1.plot(xs, np.poly1d(z)(xs), '--', color=WHITE, linewidth=1, alpha=0.5)
    ax1.set_xlabel("|D|  (dictionary size)")
    ax1.set_ylabel("time  (s)")
    ax1.set_title("W = |D| × T_h  validation", fontweight='bold')
    ax1.legend(fontsize=8)

    # Predicted vs actual scatter
    lim = max(pred.max(), pre_t.max()) * 1.1
    ax2.scatter(pred, pre_t, color=BLUE, s=55, alpha=0.8)
    ax2.plot([0, lim], [0, lim], '--', color=WHITE, linewidth=1, alpha=0.5, label="y = x  (perfect)")
    ax2.set_xlabel("predicted  W  (s)")
    ax2.set_ylabel("actual precompute  (s)")
    ax2.set_title("Mathematical Validation\nPredicted vs Observed", fontweight='bold')
    ax2.legend(fontsize=8)
    ax2.set_xlim(0, lim); ax2.set_ylim(0, lim)

    fig.suptitle("GRAPH 2 — Time vs Dictionary Size  /  Work Formula Proof",
                 fontweight='bold', fontsize=12, color=WHITE)
    fig.tight_layout()
    return fig


# ── Graph 3: CIA radar — four systems ────────────────────────────────────────
def plot_cia(r: dict) -> plt.Figure:
    fig = plt.figure(figsize=(13, 6), facecolor=BLACK)

    def cia(sr):
        return {
            "Confidentiality": max(0, 100 - sr),
            "Integrity":       max(0, 100 - sr * 0.85),
            "Authentication":  max(0, 100 - sr * 0.90),
        }

    keys   = ["unsalted", "salted", "stretched", "peppered"]
    avgs   = {k: sum(x["success_rate"] for x in r[k]) / len(r[k]) for k in keys}
    cats   = ["Confidentiality", "Integrity", "Authentication"]
    N      = len(cats)
    angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]

    # Bar chart
    ax_bar = fig.add_subplot(121)
    ax_bar.set_facecolor(DARK)
    x     = np.arange(N)
    width = 0.2
    for idx, (key, col, label) in enumerate(zip(keys, COLS, SYSTEMS)):
        vals = [cia(avgs[key])[c] for c in cats]
        bars = ax_bar.bar(x + idx * width - width * 1.5, vals, width,
                          color=col, alpha=0.85, label=label)
        for bar in bars:
            h = bar.get_height()
            ax_bar.text(bar.get_x() + width / 2, h + 1,
                        f"{h:.0f}", ha='center', fontsize=7, color=WHITE)

    ax_bar.set_xticks(x)
    ax_bar.set_xticklabels(cats)
    ax_bar.set_ylim(0, 115)
    ax_bar.set_ylabel("Security Score (%)")
    ax_bar.set_title("CIA Bar Comparison", fontweight='bold')
    ax_bar.legend(fontsize=8)

    # Radar
    ax_r = fig.add_subplot(122, polar=True)
    ax_r.set_facecolor(DARK)
    ax_r.tick_params(colors=WHITE)
    for key, col, label in zip(keys, COLS, SYSTEMS):
        vals = [cia(avgs[key])[c] for c in cats] + [cia(avgs[key])[cats[0]]]
        ax_r.plot(angles, vals, color=col, linewidth=2, label=label)
        ax_r.fill(angles, vals, alpha=0.08, color=col)
    ax_r.set_xticks(angles[:-1])
    ax_r.set_xticklabels(cats, color=WHITE, fontsize=9)
    ax_r.set_ylim(0, 100)
    ax_r.set_title("CIA Radar", color=WHITE, fontweight='bold', pad=18)
    ax_r.legend(loc='upper right', bbox_to_anchor=(1.4, 1.15), fontsize=8)
    ax_r.grid(color=DIM, alpha=0.4)

    fig.suptitle("GRAPH 3 — Confidentiality / Integrity / Authentication",
                 fontweight='bold', fontsize=12, color=WHITE)
    fig.tight_layout()
    return fig


# ── Graph 4: Latency overhead — four systems ─────────────────────────────────
def plot_latency(r: dict) -> plt.Figure:
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 6), facecolor=BLACK)
    for ax in (ax1, ax2):
        ax.set_facecolor(DARK)

    keys  = ["unsalted", "salted", "stretched", "peppered"]
    times = [[x["attack_time"] for x in r[k]] for k in keys]
    ids   = [x["test_id"] for x in r["unsalted"]]

    for t, col, label, mk in zip(times, COLS, SYSTEMS, MARKS):
        ax1.plot(ids, t, color=col, marker=mk, linewidth=1.5,
                 markersize=4, label=label, alpha=0.85)

    ax1.set_xlabel("Test ID")
    ax1.set_ylabel("Attack Time  (s)")
    ax1.set_title("Per-Test Attack Time\n(All Systems)", fontweight='bold')
    ax1.legend(fontsize=8)
    ax1.set_yscale('log')

    bp = ax2.boxplot(times, patch_artist=True,
                     labels=SYSTEMS,
                     medianprops=dict(color=WHITE, linewidth=2))
    for patch, col in zip(bp['boxes'], COLS):
        patch.set_facecolor(col)
        patch.set_alpha(0.75)
    ax2.set_ylabel("Attack Time  (s)  [log]")
    ax2.set_title("Latency Distribution\n(box plot)", fontweight='bold')
    ax2.set_yscale('log')

    fig.suptitle("GRAPH 4 — Attack vs Prevention Latency Overhead",
                 fontweight='bold', fontsize=12, color=WHITE)
    fig.tight_layout()
    return fig


# ── Graph 5: Security improvement % ─────────────────────────────────────────
def plot_improvement(r: dict) -> plt.Figure:
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 6), facecolor=BLACK)
    for ax in (ax1, ax2):
        ax.set_facecolor(DARK)

    ids = [x["test_id"] for x in r["unsalted"]]
    u_sr = np.array([x["success_rate"] for x in r["unsalted"]])

    for key, col, label in zip(
        ["salted", "stretched", "peppered"],
        [BLUE, AMBER, GREEN],
        ["Salted", "Stretched", "Peppered"],
    ):
        other_sr = np.array([x["success_rate"] for x in r[key]])
        delta = u_sr - other_sr
        ax1.bar(ids, delta, color=col, alpha=0.7, label=label,
                bottom=0, width=0.25,
                align='center')

    ax1.axhline(90, color=WHITE, linestyle='--', linewidth=0.8, alpha=0.5)
    ax1.set_xlabel("Test ID")
    ax1.set_ylabel("Improvement over Unsalted  (pp)")
    ax1.set_title("Security Gain vs Unsalted Baseline", fontweight='bold')
    ax1.legend(fontsize=8)

    # Grouped bar — average
    avgs  = [
        sum(x["success_rate"] for x in r[k]) / len(r[k])
        for k in ["unsalted", "salted", "stretched", "peppered"]
    ]
    x = np.arange(len(SYSTEMS))
    bars = ax2.bar(x, avgs, color=COLS, alpha=0.85, edgecolor=WHITE, linewidth=0.5)
    for bar, val in zip(bars, avgs):
        ax2.text(bar.get_x() + bar.get_width() / 2, val + 1,
                 f"{val:.1f}%", ha='center', fontsize=9, color=WHITE)
    ax2.set_xticks(x)
    ax2.set_xticklabels(SYSTEMS)
    ax2.set_ylim(0, 115)
    ax2.set_ylabel("Average Attack Success Rate  (%)")
    ax2.set_title("Mean Success Rate — All Systems", fontweight='bold')

    fig.suptitle("GRAPH 5 — Security Improvement Across Prevention Methods",
                 fontweight='bold', fontsize=12, color=WHITE)
    fig.tight_layout()
    return fig


# ── Graph 6: Work complexity — log-scale comparison ─────────────────────────
def plot_work_complexity(r: dict) -> plt.Figure:
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 6), facecolor=BLACK)
    for ax in (ax1, ax2):
        ax.set_facecolor(DARK)

    u = r["unsalted"]
    sizes  = np.array([x["dict_size"]  for x in u])
    W_u    = np.array([x["predicted_W"] for x in u])
    W_s    = np.array([x["dict_size"] * x["num_users"] * x["hash_time"] for x in u])
    K      = r["stretched"][0]["K"]
    W_st   = np.array([x["dict_size"] * x["num_users"] * K * x["hash_time"] for x in u])

    ax1.scatter(sizes, W_u,  color=RED,   s=45, alpha=0.8, label="Unsalted")
    ax1.scatter(sizes, W_s,  color=BLUE,  s=45, alpha=0.8, label="Salted")
    ax1.scatter(sizes, W_st, color=AMBER, s=45, alpha=0.8, label=f"Stretched K={K:,}")
    ax1.set_xlabel("|D|  (dictionary size)")
    ax1.set_ylabel("Theoretical Work W  (s)  [log]")
    ax1.set_title("Work Complexity vs |D|", fontweight='bold')
    ax1.set_yscale('log')
    ax1.legend(fontsize=8)

    # Hash clustering
    clusters = np.array([x["hash_clusters"] for x in u])
    reuse    = np.array([x["reuse_prob"]     for x in u])
    n_users  = np.array([x["num_users"]      for x in u])
    sc = ax2.scatter(n_users, clusters, c=reuse, cmap='RdYlGn_r',
                     s=60, alpha=0.85, edgecolors=WHITE, linewidths=0.3)
    cb = fig.colorbar(sc, ax=ax2)
    cb.set_label("Reuse Probability", color=WHITE)
    cb.ax.yaxis.set_tick_params(color=WHITE)
    plt.setp(cb.ax.yaxis.get_ticklabels(), color=WHITE)
    ax2.set_xlabel("Number of Users  N")
    ax2.set_ylabel("Duplicate Hash Clusters")
    ax2.set_title("Hash Clustering\n(unsalted weakness)", fontweight='bold')

    fig.suptitle("GRAPH 6 — Work Complexity & Hash Clustering",
                 fontweight='bold', fontsize=12, color=WHITE)
    fig.tight_layout()
    return fig


def generate_all_graphs(results: dict) -> list:
    return [
        plot_success_rate(results),
        plot_work_validation(results),
        plot_cia(results),
        plot_latency(results),
        plot_improvement(results),
        plot_work_complexity(results),
    ]