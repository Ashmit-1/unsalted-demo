"""
Attack attempts against the salted password system.

Demonstrates two attack strategies and why both fail:
  1. Rainbow Table Reuse   — fails instantly (0% success)
  2. Per-User Brute Force  — O(N × |D|) — impractical at scale
"""

import time
from sha256_manual import sha256


def attempt_rainbow_on_salted(salted_db: dict, rainbow_table: dict) -> tuple:
    """
    Reuse a precomputed rainbow table against salted hashes.

    Since every hash includes a unique salt, the table entries never match.
    Expected success rate: 0%

    Returns:
        (cracked_dict, elapsed_seconds)
    """
    start = time.perf_counter()
    cracked = {}
    for username, (salt, h) in salted_db.items():
        # Direct lookup — will never match because the table was built without salts
        if h in rainbow_table:
            cracked[username] = rainbow_table[h]
    elapsed = time.perf_counter() - start
    return cracked, elapsed


def bruteforce_salted(salted_db: dict, dictionary: list, max_users: int = 15) -> tuple:
    """
    Per-user dictionary attack: rehash every candidate with each user's salt.

    Complexity: O(N × |D| × T_h) — grows linearly with both N and |D|.
    For demonstration, capped at max_users to keep runtime manageable.

    Returns:
        (cracked_dict, elapsed_seconds, users_attempted)
    """
    start = time.perf_counter()
    cracked = {}
    users_subset = list(salted_db.items())[:max_users]

    for username, (salt, stored_hash) in users_subset:
        for word in dictionary:
            if sha256(salt + word) == stored_hash:
                cracked[username] = word
                break

    elapsed = time.perf_counter() - start
    return cracked, elapsed, len(users_subset)


def estimate_salted_work(num_users: int, dict_size: int, hash_time_sec: float) -> dict:
    """
    Estimate the theoretical work needed to crack a salted database.

    Returns a dict with work estimates for comparison.
    """
    unsalted_work = dict_size * hash_time_sec
    salted_work = num_users * dict_size * hash_time_sec
    salt_space_bits = 128
    exhaustive_work = (2 ** salt_space_bits) * dict_size * hash_time_sec

    return {
        "unsalted_W": unsalted_work,
        "salted_W": salted_work,
        "speedup_factor_N": num_users,
        "salt_space_bits": salt_space_bits,
        "exhaustive_W_years": exhaustive_work / (365.25 * 24 * 3600),
    }
