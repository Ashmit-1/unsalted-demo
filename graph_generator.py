"""
Generate all required comparison graphs (minimum 4 mandatory + extras).

Mandatory:
  1. Before vs After Attack Success Rate
  2. Time vs Dictionary Size (W = |D| × T_h)
  3. CIA (Confidentiality / Integrity / Authentication) Rate
  4. Attack vs Prevention Latency Overhead

Additional:
  5. Security Improvement Percentage per test
  6. Hash Clustering — password reuse visualised
"""

import matplotlib
matplotlib.use('Agg')  # non-interactive backend for thread safety
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# ── Colour palette ───────────────────────────────────────────────────────────
RED    = "#e74c3c"
GREEN  = "#2ecc71"
BLUE   = "#3498db"
ORANGE = "#f39c12"
PURPLE = "#9b59b6"
DARK   = "#2c3e50"
LIGHT  = "#ecf0f1"

plt.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor":   "#f8f9fa",
    "axes.grid":        True,
    "grid.alpha":       0.3,
    "axes.spines.top":  False,
    "axes.spines.right": False,
    "font.size":        11,
})


# ── Graph 1: Before vs After Attack Success Rate ─────────────────────────────
def plot_success_rate_comparison(unsalted: list, salted: list) -> plt.Figure:
    fig, ax = plt.subplots(figsize=(11, 6))

    ids  = [r["test_id"]      for r in unsalted]
    u_sr = [r["success_rate"] for r in unsalted]
    s_sr = [r["success_rate"] for r in salted]

    ax.plot(ids, u_sr, color=RED,   marker='o', linewidth=2,
            markersize=5, label="Unsalted SHA-256 (Vulnerable)")
    ax.plot(ids, s_sr, color=GREEN, marker='s', linewidth=2,
            markersize=5, label="Salted SHA-256 (Secure)")
    ax.axhline(y=90, color=ORANGE, linestyle='--', linewidth=1.5,
               label="90 % Attack-Success Threshold")

    ax.fill_between(ids, u_sr, alpha=0.12, color=RED)
    ax.fill_between(ids, s_sr, alpha=0.12, color=GREEN)

    avg_u = sum(u_sr) / len(u_sr)
    avg_s = sum(s_sr) / len(s_sr)
    ax.axhline(y=avg_u, color=RED,   linestyle=':', linewidth=1,
               label=f"Avg Unsalted {avg_u:.1f}%")
    ax.axhline(y=avg_s, color=GREEN, linestyle=':', linewidth=1,
               label=f"Avg Salted  {avg_s:.1f}%")

    ax.set_xlabel("Test Case ID")
    ax.set_ylabel("Attack Success Rate (%)")
    ax.set_title("Graph 1 — Before vs After Prevention: Attack Success Rate",
                 fontweight='bold', pad=12)
    ax.set_ylim(-5, 110)
    ax.set_xlim(0.5, len(ids) + 0.5)
    ax.legend(loc='center right', fontsize=9)

    # Vulnerability band annotation
    ax.annotate("VULNERABLE ZONE", xy=(len(ids) * 0.5, 95),
                fontsize=9, color=RED, alpha=0.6, ha='center')
    ax.annotate("SECURE ZONE", xy=(len(ids) * 0.5, 5),
                fontsize=9, color=GREEN, alpha=0.7, ha='center')

    fig.tight_layout()
    return fig


# ── Graph 2: Time vs Dictionary Size ─────────────────────────────────────────
def plot_time_vs_dict_size(unsalted: list) -> plt.Figure:
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 6))

    sizes  = np.array([r["dict_size"]       for r in unsalted])
    pre_t  = np.array([r["precompute_time"] for r in unsalted])
    tot_t  = np.array([r["attack_time"]     for r in unsalted])
    pred_W = np.array([r["predicted_W"]     for r in unsalted])

    # — Left: scatter of actual times vs |D| —
    ax1.scatter(sizes, pre_t, c=BLUE,   alpha=0.75, s=60, label="Precompute Time (actual)")
    ax1.scatter(sizes, tot_t, c=RED,    alpha=0.75, s=60, label="Total Attack Time")
    ax1.scatter(sizes, pred_W, c=GREEN, alpha=0.75, s=60, marker='^',
                label="Predicted W = |D|·T_h")

    # Linear trend
    z = np.polyfit(sizes, pre_t, 1)
    p = np.poly1d(z)
    xs = np.linspace(sizes.min(), sizes.max(), 200)
    ax1.plot(xs, p(xs), '--', color=BLUE, linewidth=1.5, alpha=0.6)

    ax1.set_xlabel("Dictionary Size  |D|")
    ax1.set_ylabel("Time (seconds)")
    ax1.set_title("Precompute Time vs |D|", fontweight='bold')
    ax1.legend(fontsize=8)

    # — Right: scatter of predicted vs actual (should be ≈ diagonal) —
    ax2.scatter(pred_W, pre_t, c=PURPLE, alpha=0.75, s=60)
    lim = max(pred_W.max(), pre_t.max()) * 1.1
    ax2.plot([0, lim], [0, lim], 'k--', linewidth=1.2, label="y = x  (perfect match)")
    ax2.set_xlabel("Predicted  W = |D| × T_h  (sec)")
    ax2.set_ylabel("Actual Precompute Time (sec)")
    ax2.set_title("Mathematical Validation\nW = |D| × T_h", fontweight='bold')
    ax2.legend(fontsize=8)
    ax2.set_xlim(0, lim)
    ax2.set_ylim(0, lim)

    fig.suptitle("Graph 2 — Time vs Dictionary Size  (W = |D| × T_h)",
                 fontweight='bold', fontsize=13, y=1.01)
    fig.tight_layout()
    return fig


# ── Graph 3: CIA Rate ─────────────────────────────────────────────────────────
def plot_cia_comparison(unsalted: list, salted: list) -> plt.Figure:
    fig, axes = plt.subplots(1, 2, figsize=(13, 6))

    avg_u = sum(r["success_rate"] for r in unsalted) / len(unsalted)
    avg_s = sum(r["success_rate"] for r in salted)   / len(salted)

    # Derive CIA scores
    # Confidentiality — % of passwords NOT recovered
    # Integrity       — whether stored data can be trusted (correlated with cracked rate)
    # Authentication  — how reliably the system can distinguish legit vs attacker

    def cia_scores(crack_rate: float) -> dict:
        c = max(0.0, 100.0 - crack_rate)
        i = max(0.0, 100.0 - crack_rate * 0.85)
        a = max(0.0, 100.0 - crack_rate * 0.90)
        return {"Confidentiality": c, "Integrity": i, "Authentication": a}

    u_cia = cia_scores(avg_u)
    s_cia = cia_scores(avg_s)

    cats  = list(u_cia.keys())
    x     = np.arange(len(cats))
    width = 0.35

    # — Bar chart —
    ax = axes[0]
    b1 = ax.bar(x - width / 2, [u_cia[c] for c in cats], width,
                color=RED,   alpha=0.85, label="Unsalted (Vulnerable)")
    b2 = ax.bar(x + width / 2, [s_cia[c] for c in cats], width,
                color=GREEN, alpha=0.85, label="Salted (Secure)")

    for bar in [*b1, *b2]:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 1,
                f"{h:.1f}%", ha='center', va='bottom', fontsize=9)

    ax.set_xticks(x)
    ax.set_xticklabels(cats)
    ax.set_ylim(0, 118)
    ax.set_ylabel("Security Score (%)")
    ax.set_title("CIA Security Scores", fontweight='bold')
    ax.legend()

    # — Radar / spider chart —
    ax2 = axes[1]
    categories = cats + [cats[0]]   # close the polygon
    N = len(cats)
    angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]

    u_vals = [u_cia[c] for c in cats] + [u_cia[cats[0]]]
    s_vals = [s_cia[c] for c in cats] + [s_cia[cats[0]]]

    ax2 = fig.add_subplot(122, polar=True)
    ax2.plot(angles, u_vals, color=RED,   linewidth=2, label="Unsalted")
    ax2.fill(angles, u_vals, color=RED,   alpha=0.20)
    ax2.plot(angles, s_vals, color=GREEN, linewidth=2, label="Salted")
    ax2.fill(angles, s_vals, color=GREEN, alpha=0.20)

    ax2.set_xticks(angles[:-1])
    ax2.set_xticklabels(cats, fontsize=10)
    ax2.set_ylim(0, 100)
    ax2.set_title("CIA Radar", fontweight='bold', pad=15)
    ax2.legend(loc='upper right', bbox_to_anchor=(1.3, 1.15), fontsize=9)

    fig.suptitle("Graph 3 — Confidentiality / Integrity / Authentication Rate",
                 fontweight='bold', fontsize=13)
    fig.tight_layout()
    return fig


# ── Graph 4: Attack vs Prevention Latency Overhead ───────────────────────────
def plot_latency_overhead(unsalted: list, salted: list) -> plt.Figure:
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 6))

    ids    = np.array([r["test_id"]    for r in unsalted])
    u_pre  = np.array([r["precompute_time"] for r in unsalted])
    u_look = np.array([r["lookup_time"]     for r in unsalted])
    s_time = np.array([r["attack_time"]     for r in salted])

    # — Stacked bar: breakdown of unsalted attack time —
    ax1.bar(ids, u_pre,  color=BLUE,   label="Precompute (build table)", alpha=0.85)
    ax1.bar(ids, u_look, bottom=u_pre, color=RED, label="Lookup (crack DB)", alpha=0.85)
    ax1.plot(ids, s_time, color=GREEN, marker='D', linewidth=2, markersize=5,
             label="Salted (failed) attack time")

    ax1.set_xlabel("Test Case ID")
    ax1.set_ylabel("Time (seconds)")
    ax1.set_title("Per-Test Attack Time Breakdown", fontweight='bold')
    ax1.legend(fontsize=8)

    # — Box plots: distribution comparison —
    data   = [u_pre, u_look, s_time]
    labels = ["Precompute\n(unsalted)", "Lookup\n(unsalted)", "Salted\nAttempt"]
    colours= [BLUE, RED, GREEN]

    bp = ax2.boxplot(data, patch_artist=True, labels=labels,
                     medianprops=dict(color='black', linewidth=2))
    for patch, col in zip(bp['boxes'], colours):
        patch.set_facecolor(col)
        patch.set_alpha(0.75)

    ax2.set_ylabel("Time (seconds)")
    ax2.set_title("Latency Distribution\n(Unsalted Attack vs Salted Defence)", fontweight='bold')

    fig.suptitle("Graph 4 — Attack vs Prevention Latency Overhead",
                 fontweight='bold', fontsize=13)
    fig.tight_layout()
    return fig


# ── Graph 5: Security Improvement % ─────────────────────────────────────────
def plot_security_improvement(unsalted: list, salted: list) -> plt.Figure:
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 6))

    ids = [r["test_id"] for r in unsalted]
    improvements = [u["success_rate"] - s["success_rate"]
                    for u, s in zip(unsalted, salted)]
    colours = [GREEN if v >= 80 else ORANGE for v in improvements]

    ax1.bar(ids, improvements, color=colours, alpha=0.85, edgecolor='white')
    ax1.axhline(y=90, color=RED, linestyle='--', linewidth=1.5, label="90% target")
    ax1.set_xlabel("Test Case ID")
    ax1.set_ylabel("Improvement in Attack Success Rate (pp)")
    ax1.set_title("Security Improvement\n(Unsalted → Salted)", fontweight='bold')
    ax1.set_ylim(0, 115)
    ax1.legend()

    green_patch = mpatches.Patch(color=GREEN, label='≥ 80 pp improvement')
    orange_patch = mpatches.Patch(color=ORANGE, label='< 80 pp improvement')
    ax1.legend(handles=[green_patch, orange_patch,
               mpatches.Patch(color=RED, label='90% target')], fontsize=8)

    # — Cumulative improvement —
    cum = np.cumsum(improvements)
    ax2.plot(ids, cum, color=PURPLE, linewidth=2, marker='o', markersize=4)
    ax2.fill_between(ids, 0, cum, alpha=0.15, color=PURPLE)
    ax2.set_xlabel("Test Case ID")
    ax2.set_ylabel("Cumulative Improvement (pp)")
    ax2.set_title("Cumulative Security Gain\nAcross All Tests", fontweight='bold')

    fig.suptitle("Graph 5 — Security Improvement: Salting vs No Salting",
                 fontweight='bold', fontsize=13)
    fig.tight_layout()
    return fig


# ── Graph 6: Hash Clustering (password reuse) ────────────────────────────────
def plot_hash_clustering(unsalted: list) -> plt.Figure:
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 6))

    n_users   = [r["num_users"]    for r in unsalted]
    clusters  = [r["hash_clusters"] for r in unsalted]
    reuse     = [r["reuse_prob"]    for r in unsalted]

    sc = ax1.scatter(n_users, clusters, c=reuse, cmap='RdYlGn_r',
                     s=70, alpha=0.85, edgecolors='white', linewidths=0.5)
    cbar = fig.colorbar(sc, ax=ax1)
    cbar.set_label("Reuse Probability", fontsize=9)
    ax1.set_xlabel("Number of Users (N)")
    ax1.set_ylabel("Hash Clusters (identical hashes)")
    ax1.set_title("Hash Clustering vs User Count\n(higher = more vulnerable)", fontweight='bold')

    # — Reuse probability distribution —
    ax2.hist(reuse, bins=10, color=ORANGE, alpha=0.85, edgecolor='white')
    ax2.set_xlabel("Reuse Probability")
    ax2.set_ylabel("Test Count")
    ax2.set_title("Distribution of Reuse Probabilities\nAcross Tests", fontweight='bold')

    fig.suptitle("Graph 6 — Password Reuse & Hash Clustering (Unsalted Weakness)",
                 fontweight='bold', fontsize=13)
    fig.tight_layout()
    return fig


# ── Public entry point ────────────────────────────────────────────────────────
def generate_all_graphs(comparison_results: dict) -> list:
    """Return a list of all matplotlib Figure objects."""
    u = comparison_results["unsalted"]
    s = comparison_results["salted"]

    figs = [
        plot_success_rate_comparison(u, s),
        plot_time_vs_dict_size(u),
        plot_cia_comparison(u, s),
        plot_latency_overhead(u, s),
        plot_security_improvement(u, s),
        plot_hash_clustering(u),
    ]
    return figs
