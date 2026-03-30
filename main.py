"""
Main entry point — Final Review.

Runs the full comparative experiment suite (unsalted vs salted)
and prints a detailed report including mathematical validation.
Launch the GUI with:  python gui.py
"""

from experiments import run_test_suite
from comparison_runner import run_comparison
from export_results import export_to_csv
from metrics import estimate_work_unsalted, estimate_work_salted


def separator(title=""):
    if title:
        print(f"\n{'=' * 70}")
        print(f"  {title}")
        print('=' * 70)
    else:
        print('─' * 70)


def main():
    separator("FINAL REVIEW — PASSWORD HASH ATTACK & PREVENTION")
    print("  Unsalted SHA-256 (Vulnerable) vs Salted SHA-256 (Secure)")
    separator()

    # ── Part 1: Unsalted-only baseline (25 tests) ────────────────────────
    separator("PART 1 — UNSALTED ATTACK BASELINE (25 Tests)")
    print()
    baseline = run_test_suite(num_tests=25, dict_base_size=2000)

    sr_list  = [r["success_rate"]    for r in baseline]
    at_list  = [r["total_attack_time"] for r in baseline]
    pre_list = [r["precompute_time"] for r in baseline]
    lk_list  = [r["lookup_time"]     for r in baseline]

    avg_sr  = sum(sr_list)  / len(sr_list)
    avg_at  = sum(at_list)  / len(at_list)
    avg_pre = sum(pre_list) / len(pre_list)
    avg_lk  = sum(lk_list)  / len(lk_list)
    ge90    = sum(1 for s in sr_list if s >= 90)

    separator("UNSALTED SUMMARY")
    print(f"  Tests >= 90% success : {ge90}/{len(baseline)} "
          f"({ge90/len(baseline)*100:.0f}%)")
    print(f"  Average success rate : {avg_sr:.1f}%")
    print(f"  Average attack time  : {avg_at:.4f} s")
    print(f"  Average precompute   : {avg_pre:.4f} s")
    print(f"  Average lookup       : {avg_lk:.6f} s")

    # ── Part 2: Full comparative (25 paired tests) ────────────────────────
    separator("PART 2 — COMPARATIVE ANALYSIS (25 Paired Tests)")
    print()

    def cb(tid, nu, ds, u_sr, s_sr, u_t):
        print(f"  [{tid:2d}] N={nu:3d} |D|={ds:4d}  "
              f"Unsalted={u_sr:5.1f}%  Salted={s_sr:4.1f}%  "
              f"t={u_t:.4f}s")

    results = run_comparison(num_tests=25, dict_base_size=2000, callback=cb)
    s = results["summary"]

    separator("COMPARATIVE SUMMARY")
    print(f"  Unsalted avg success  : {s['avg_unsalted_rate']:.1f}%")
    print(f"  Salted   avg success  : {s['avg_salted_rate']:.1f}%")
    print(f"  Security improvement  : {s['avg_security_improvement']:.1f} percentage points")
    print(f"  Unsalted tests ≥ 90%  : {s['tests_ge90_unsalted']}/{s['num_tests']}")
    print(f"  Avg unsalted time     : {s['avg_unsalted_time']:.4f} s")
    print(f"  Avg salted    time    : {s['avg_salted_time']:.6f} s")

    # ── Part 3: Mathematical Validation ──────────────────────────────────
    separator("PART 3 — MATHEMATICAL VALIDATION")
    print()
    print("  UNSALTED:  W = |D| × T_h   (one precomputation attacks all N users)")
    print("  SALTED:    W = N × |D| × T_h   (rainbow table defeated; must redo per user)")
    print()
    print(f"  {'Test':>4}  {'|D|':>5}  {'T_h (s)':>10}  "
          f"{'Predicted W':>12}  {'Actual t':>10}  {'Error%':>7}")
    separator()

    for r in results["unsalted"][:10]:
        ds   = r["dict_size"]
        ht   = r["hash_time"]
        pred = r["predicted_W"]
        act  = r["precompute_time"]
        err  = abs(pred - act) / act * 100 if act > 0 else 0
        print(f"  {r['test_id']:>4}  {ds:>5}  {ht:>10.6f}  "
              f"{pred:>12.5f}  {act:>10.5f}  {err:>6.1f}%")

    print()
    print("  SALTED work multiplier (N factor):")
    for r in results["salted"][:5]:
        print(f"    Test {r['test_id']:2d}: N={r['num_users']:3d}  "
              f"Salted_W ≈ {r['salted_W_estimate']:.4f}s  "
              f"(×{r['speedup_factor']:3d} harder than unsalted)")

    # ── Part 4: Independence of N ─────────────────────────────────────────
    separator("PART 4 — INDEPENDENCE FROM N")
    u_data = sorted(results["unsalted"], key=lambda r: r["num_users"])
    small  = [r for r in u_data if r["num_users"] <= 150]
    large  = [r for r in u_data if r["num_users"] >= 350]

    if small and large:
        t_s = sum(r["attack_time"] for r in small) / len(small)
        t_l = sum(r["attack_time"] for r in large) / len(large)
        n_s = sum(r["num_users"]   for r in small) / len(small)
        n_l = sum(r["num_users"]   for r in large) / len(large)
        print(f"\n  Small N (avg {n_s:.0f} users): avg attack time = {t_s:.4f}s")
        print(f"  Large N (avg {n_l:.0f} users): avg attack time = {t_l:.4f}s")
        print(f"  → Attack time is approximately independent of N (unsalted).")
        print(f"  → Salted system forces O(N × |D|) — attack scales with N.")

    # ── Export ────────────────────────────────────────────────────────────
    separator("EXPORT")
    export_to_csv(baseline, "results_unsalted.csv")
    _export_comparison(results)

    separator()
    print("\n  Done.  Launch GUI with:  python gui.py")
    print()


def _export_comparison(results: dict):
    import csv
    rows = []
    for ur, sr in zip(results["unsalted"], results["salted"]):
        rows.append({
            "test_id":       ur["test_id"],
            "num_users":     ur["num_users"],
            "dict_size":     ur["dict_size"],
            "unsalted_sr":   round(ur["success_rate"], 2),
            "salted_sr":     round(sr["success_rate"], 2),
            "unsalted_time": round(ur["attack_time"], 6),
            "salted_time":   round(sr["attack_time"], 6),
            "improvement":   round(ur["success_rate"] - sr["success_rate"], 2),
        })
    with open("results_comparison.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print("Results exported to results_comparison.csv")


if __name__ == "__main__":
    main()
