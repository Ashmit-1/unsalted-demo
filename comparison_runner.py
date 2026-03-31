"""
Four-way comparative experiment runner.

Systems compared:
  0. Unsalted SHA-256          — W = |D| × T_h
  1. Salted SHA-256            — W = N × |D| × T_h
  2. Key-Stretched (K=1000)   — W = N × |D| × K × T_h
  3. Salt + Pepper (256-bit)  — W = 2²⁵⁶ × N × |D| × T_h
"""

import random
from database_generator import generate_dictionary, generate_users
from hash_systems import hash_database, hash_database_salted
from attackers import build_rainbow_table, crack_database, attempt_rainbow_on_salted
from preventions import (
    hash_database_stretched, attempt_rainbow_on_stretched, ITERATIONS,
    hash_database_peppered, attempt_rainbow_on_peppered, get_server_pepper,
)
from metrics import calculate_success_rate


def run_full_comparison(
    num_tests=25,
    dict_base_size=2000,
    k_iter=ITERATIONS,
    log_cb=None,
    progress_cb=None,
    stop_event=None,
    test_cb=None,           # called after each test: (u_sr, s_sr, st_sr, p_sr)
) -> dict:

    def log(msg, tag=""):
        if log_cb:
            log_cb(msg, tag)

    full_dictionary = generate_dictionary(dict_base_size)
    results = {"unsalted": [], "salted": [], "stretched": [], "peppered": []}
    pepper = get_server_pepper()

    log("", "")
    log("  W O R K   F O R M U L A S", "head")
    log("  " + "─" * 50, "dim")
    log("  Unsalted  :  W = |D| × T_h", "math")
    log("  Salted    :  W = N × |D| × T_h", "math")
    log(f"  Stretched :  W = N × |D| × K × T_h   K={k_iter:,}", "math")
    log("  Peppered  :  W = 2²⁵⁶ × N × |D| × T_h  ≈ ∞", "math")
    log("", "")

    for i in range(num_tests):
        if stop_event and stop_event.is_set():
            break

        num_users  = random.randint(50, 500)
        reuse_prob = round(random.uniform(0.5, 0.9), 2)
        dict_size  = random.randint(len(full_dictionary) // 2, len(full_dictionary))
        dictionary = random.sample(full_dictionary, dict_size)
        users      = generate_users(num_users, dictionary, reuse_prob)

        log(f"  ╔═ TEST {i+1:02d}  N={num_users}  |D|={dict_size:,}  reuse={reuse_prob:.0%} {'═'*20}", "head")

        # Shared rainbow table
        rt, pre_t = build_rainbow_table(dictionary)
        T_h = pre_t / dict_size

        log(f"  ║  T_h = {pre_t:.6f}s ÷ {dict_size:,} = {T_h:.8f} s/hash", "math")

        # ── Unsalted ──────────────────────────────────────────────────
        hdb, freq = hash_database(users)
        cracked_u, lk_u = crack_database(hdb, rt)
        u_sr = calculate_success_rate(len(cracked_u), num_users)
        W_u  = dict_size * T_h
        log(f"  ║  [UNSALTED]   W = {dict_size:,} × {T_h:.8f} = {W_u:.6f}s"
            f"   SR={u_sr:.0f}%  ⚠", "err")

        # feature 4 — entropy / clustering
        dup_groups = {h: c for h, c in freq.items() if c > 1}
        if dup_groups:
            worst_h, worst_c = max(dup_groups.items(), key=lambda x: x[1])
            log(f"  ║  ⚑ {len(dup_groups)} shared hashes — worst: {worst_c} accounts"
                f" share {worst_h[:16]}…", "warn")
            log(f"  ║    cracking that ONE hash instantly exposes {worst_c} accounts", "warn")

        # ── Salted ────────────────────────────────────────────────────
        sdb = hash_database_salted(users)
        cracked_s, lk_s = attempt_rainbow_on_salted(sdb, rt)
        s_sr = calculate_success_rate(len(cracked_s), num_users)
        W_s  = num_users * dict_size * T_h
        log(f"  ║  [SALTED]     W = {num_users}×{dict_size:,}×T_h = {W_s:.4f}s  (×{num_users})"
            f"   SR={s_sr:.0f}%  ✔", "ok")

        # ── Stretched ─────────────────────────────────────────────────
        stdb = hash_database_stretched(users, iterations=k_iter)
        cracked_st, lk_st = attempt_rainbow_on_stretched(stdb, rt)
        st_sr = calculate_success_rate(len(cracked_st), num_users)
        W_st  = num_users * dict_size * k_iter * T_h
        log(f"  ║  [STRETCHED]  W = {num_users}×{dict_size:,}×{k_iter:,}×T_h = {W_st:.2f}s  (×{num_users*k_iter:,})"
            f"   SR={st_sr:.0f}%  ✔", "ok")

        # feature 5 — login cost vs attack cost
        login_ms       = k_iter * T_h * 1000
        attack_per_usr = k_iter * dict_size * T_h
        log(f"  ║    ⟳ defender login  : {login_ms:.1f} ms/user  (K={k_iter:,}×T_h)", "math")
        log(f"  ║    ⚔ attacker/user   : {attack_per_usr:.3f} s  (K×|D|×T_h)  — impractical", "math")

        # ── Peppered ──────────────────────────────────────────────────
        pdb = hash_database_peppered(users, pepper=pepper)
        cracked_p, lk_p = attempt_rainbow_on_peppered(pdb, rt)
        p_sr = calculate_success_rate(len(cracked_p), num_users)
        W_p_yr = (2**256) * num_users * dict_size * T_h / (365.25 * 24 * 3600)
        log(f"  ║  [PEPPERED]   W ≈ {W_p_yr:.2e} years  (2²⁵⁶×N×|D|×T_h)"
            f"   SR={p_sr:.0f}%  ✔", "ok")
        log(f"  ╚{'═'*58}", "dim")
        log("", "")

        results["unsalted"].append({
            "test_id": i+1, "num_users": num_users, "dict_size": dict_size,
            "success_rate": u_sr, "attack_time": pre_t + lk_u,
            "precompute_time": pre_t, "lookup_time": lk_u,
            "cracked": len(cracked_u), "hash_time": T_h,
            "predicted_W": W_u, "reuse_prob": reuse_prob,
            "hash_clusters": sum(1 for c in freq.values() if c > 1),
        })
        results["salted"].append({
            "test_id": i+1, "num_users": num_users, "dict_size": dict_size,
            "success_rate": s_sr, "attack_time": lk_s, "cracked": len(cracked_s),
            "salted_W": W_s, "speedup": num_users,
        })
        results["stretched"].append({
            "test_id": i+1, "num_users": num_users, "dict_size": dict_size,
            "success_rate": st_sr, "attack_time": lk_st, "cracked": len(cracked_st),
            "stretched_W": W_st, "K": k_iter, "speedup": num_users * k_iter,
        })
        results["peppered"].append({
            "test_id": i+1, "num_users": num_users, "dict_size": dict_size,
            "success_rate": p_sr, "attack_time": lk_p, "cracked": len(cracked_p),
            "work_years": W_p_yr,
        })

        if test_cb:
            test_cb(u_sr, s_sr, st_sr, p_sr)
        if progress_cb:
            progress_cb((i + 1) / num_tests * 100)

    results["summary"] = _summarise(results)
    _log_final(log, results["summary"])
    return results


def _summarise(results):
    def avg(lst, k):
        v = [r[k] for r in lst]
        return sum(v) / len(v) if v else 0
    u, s, st, p = results["unsalted"], results["salted"], results["stretched"], results["peppered"]
    return {
        "num_tests": len(u),
        "avg_unsalted_sr":    avg(u,  "success_rate"),
        "avg_salted_sr":      avg(s,  "success_rate"),
        "avg_stretched_sr":   avg(st, "success_rate"),
        "avg_peppered_sr":    avg(p,  "success_rate"),
        "avg_unsalted_time":  avg(u,  "attack_time"),
        "avg_salted_time":    avg(s,  "attack_time"),
        "avg_stretched_time": avg(st, "attack_time"),
        "avg_peppered_time":  avg(p,  "attack_time"),
        "tests_ge90":         sum(1 for r in u if r["success_rate"] >= 90),
        "K_iterations":       st[0]["K"] if st else ITERATIONS,
    }


def _log_final(log, s):
    log("", "")
    log("  ╔══════════════════════════════════════════════════════╗", "head")
    log("  ║       F I N A L   C O M P A R A T I V E            ║", "head")
    log("  ╚══════════════════════════════════════════════════════╝", "head")
    log(f"  {'System':<18} {'Avg SR':>8}  {'Work Formula'}", "info")
    log("  " + "─" * 60, "dim")
    log(f"  {'Unsalted':<18} {s['avg_unsalted_sr']:>7.1f}%  W = |D| × T_h", "err")
    log(f"  {'Salted':<18} {s['avg_salted_sr']:>7.1f}%  W = N × |D| × T_h", "ok")
    log(f"  {'Stretched':<18} {s['avg_stretched_sr']:>7.1f}%  W = N × |D| × {s['K_iterations']:,} × T_h", "ok")
    log(f"  {'Peppered':<18} {s['avg_peppered_sr']:>7.1f}%  W = 2²⁵⁶ × N × |D| × T_h", "ok")
    log("", "")
    log(f"  Unsalted tests ≥90%: {s['tests_ge90']}/{s['num_tests']}", "err")
    log(f"  Stretching overhead: K={s['K_iterations']:,}× per password guess", "math")
    log(f"  Pepper key space: 2²⁵⁶ ≈ 10⁷⁷  (offline attack: impossible)", "math")
    log("", "")
    # feature 3 — recommendation block
    log("  ╔══════════════════════════════════════════════════════╗", "head")
    log("  ║        R E C O M M E N D A T I O N                 ║", "head")
    log("  ╚══════════════════════════════════════════════════════╝", "head")
    log("  All three defences → 0 % attacker success rate.", "ok")
    log("  Production deployment — use all three layers together:", "info")
    log("", "")
    log("  ① Salt every password  — eliminates rainbow table reuse entirely", "ok")
    log(f"  ② Key stretching K≥10k — {s['K_iterations']:,}× attacker cost, imperceptible login delay", "ok")
    log("  ③ Pepper (server-side) — 2²⁵⁶× factor if only the DB is stolen", "ok")
    log("  ④ Use Argon2id/bcrypt  — memory-hard, industry standard for production", "warn")
    log("", "")
    log(f"  WINNER (this demo):  Peppered  — W = 2²⁵⁶ × N × |D| × T_h ≈ 10⁷⁷ years", "ok")
    log("  Minimum viable now:  bcrypt + unique salt — NEVER plain SHA-256", "warn")
    log("", "")