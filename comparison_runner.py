"""
Comparative experiment runner.

Runs identical test scenarios against BOTH the unsalted (vulnerable) system
and the salted (secure) system, then returns side-by-side results for
graphing and analysis.
"""

import random
import time

from database_generator import generate_dictionary, generate_users
from unsalted_system import hash_database
from attacker_unsalted import build_rainbow_table, crack_database
from salted_system import hash_database_salted
from attacker_salted import attempt_rainbow_on_salted, estimate_salted_work
from metrics import calculate_success_rate


def run_comparison(
    num_tests: int = 25,
    dict_base_size: int = 2000,
    callback=None,
    stop_event=None,
) -> dict:
    """
    Run num_tests paired experiments.

    For each test:
      - Same users & dictionary used for BOTH systems
      - Unsalted: build rainbow table → lookup  (fast, high success)
      - Salted:   reuse rainbow table → lookup  (fails, 0% success)

    Args:
        callback: fn(test_id, n_users, dict_sz, unsalted_sr, salted_sr, u_time)
        stop_event: threading.Event — checked between tests to allow cancellation

    Returns:
        {
          "unsalted": [...],
          "salted":   [...],
          "summary":  {...},
        }
    """
    full_dictionary = generate_dictionary(dict_base_size)
    unsalted_results = []
    salted_results   = []

    for i in range(num_tests):
        if stop_event and stop_event.is_set():
            break

        num_users  = random.randint(50, 500)
        reuse_prob = round(random.uniform(0.5, 0.9), 2)
        dict_size  = random.randint(len(full_dictionary) // 2, len(full_dictionary))
        dictionary = random.sample(full_dictionary, dict_size)

        users = generate_users(num_users, dictionary, reuse_prob)

        # ── Unsalted attack ──────────────────────────────────────────────────
        hashed_db, hash_freq = hash_database(users)
        rainbow_table, precompute_time = build_rainbow_table(dictionary)
        cracked_u, lookup_time = crack_database(hashed_db, rainbow_table)

        u_success = calculate_success_rate(len(cracked_u), num_users)
        u_time    = precompute_time + lookup_time

        # Per-hash timing for math validation
        hash_time = precompute_time / dict_size if dict_size else 0

        unsalted_results.append({
            "test_id":        i + 1,
            "num_users":      num_users,
            "dict_size":      dict_size,
            "reuse_prob":     reuse_prob,
            "success_rate":   u_success,
            "attack_time":    u_time,
            "precompute_time": precompute_time,
            "lookup_time":    lookup_time,
            "cracked":        len(cracked_u),
            "hash_clusters":  sum(1 for c in hash_freq.values() if c > 1),
            "hash_time":      hash_time,
            "predicted_W":    dict_size * hash_time,
        })

        # ── Salted attack (rainbow reuse) ────────────────────────────────────
        salted_db = hash_database_salted(users)
        cracked_s, s_time = attempt_rainbow_on_salted(salted_db, rainbow_table)

        s_success = calculate_success_rate(len(cracked_s), num_users)

        work_est = estimate_salted_work(num_users, dict_size, hash_time)

        salted_results.append({
            "test_id":              i + 1,
            "num_users":            num_users,
            "dict_size":            dict_size,
            "success_rate":         s_success,   # expected 0%
            "attack_time":          s_time,
            "cracked":              len(cracked_s),
            "salted_W_estimate":    work_est["salted_W"],
            "speedup_factor":       work_est["speedup_factor_N"],
            "salt_bits":            work_est["salt_space_bits"],
        })

        if callback:
            callback(i + 1, num_users, dict_size, u_success, s_success, u_time)

    # ── Summary statistics ───────────────────────────────────────────────────
    summary = _compute_summary(unsalted_results, salted_results)

    return {
        "unsalted": unsalted_results,
        "salted":   salted_results,
        "summary":  summary,
    }


def _compute_summary(unsalted: list, salted: list) -> dict:
    if not unsalted:
        return {}

    u_rates   = [r["success_rate"] for r in unsalted]
    s_rates   = [r["success_rate"] for r in salted]
    u_times   = [r["attack_time"]  for r in unsalted]
    s_times   = [r["attack_time"]  for r in salted]

    avg_u_rate  = sum(u_rates)  / len(u_rates)
    avg_s_rate  = sum(s_rates)  / len(s_rates)
    avg_u_time  = sum(u_times)  / len(u_times)
    avg_s_time  = sum(s_times)  / len(s_times)

    tests_ge90  = sum(1 for r in u_rates if r >= 90)
    improvement = [u - s for u, s in zip(u_rates, s_rates)]
    avg_improve = sum(improvement) / len(improvement)

    return {
        "num_tests":          len(unsalted),
        "avg_unsalted_rate":  avg_u_rate,
        "avg_salted_rate":    avg_s_rate,
        "avg_unsalted_time":  avg_u_time,
        "avg_salted_time":    avg_s_time,
        "tests_ge90_unsalted": tests_ge90,
        "pct_tests_ge90":     (tests_ge90 / len(unsalted)) * 100,
        "avg_security_improvement": avg_improve,
    }
