"""
Attack implementations — rainbow table (unsalted) and salted attack attempts.

Unsalted attack:  precompute once, crack all N users in O(1) per user.
Salted attacks:   rainbow reuse → 0 % success; brute-force → O(N × |D|).
"""

import time
from sha256_manual import sha256


# ── Rainbow table attack on unsalted hashes ──────────────────────────────────

def build_rainbow_table(dictionary: list) -> tuple:
    """
    Hash every word in the dictionary once and build a reverse lookup table.

    Cost: O(|D|) — independent of number of target users.

    Returns:
        (table, precompute_time_seconds)
        table : {hash_hex: plaintext_password}
    """
    start = time.perf_counter()
    table = {sha256(word): word for word in dictionary}
    return table, time.perf_counter() - start


def crack_database(hashed_db: dict, rainbow_table: dict) -> tuple:
    """
    Look up every user's hash in the precomputed rainbow table.

    Cost: O(N) lookups — O(1) per user.

    Returns:
        (cracked_dict, lookup_time_seconds)
        cracked_dict : {username: recovered_password}
    """
    start   = time.perf_counter()
    cracked = {
        username: rainbow_table[h]
        for username, h in hashed_db.items()
        if h in rainbow_table
    }
    return cracked, time.perf_counter() - start


# ── Attack attempts on salted hashes ─────────────────────────────────────────

def attempt_rainbow_on_salted(salted_db: dict, rainbow_table: dict) -> tuple:
    """
    Reuse a precomputed rainbow table against salted hashes.

    Since every hash includes a unique salt the table entries never match.
    Expected success rate: 0 %

    Returns:
        (cracked_dict, elapsed_seconds)
    """
    start   = time.perf_counter()
    cracked = {
        username: rainbow_table[h]
        for username, (salt, h) in salted_db.items()
        if h in rainbow_table
    }
    return cracked, time.perf_counter() - start


def bruteforce_salted(salted_db: dict, dictionary: list,
                      max_users: int = 15) -> tuple:
    """
    Per-user dictionary attack: rehash every candidate with each user's salt.

    Complexity: O(N × |D| × T_h) — capped at max_users for demo speed.

    Returns:
        (cracked_dict, elapsed_seconds, users_attempted)
    """
    start        = time.perf_counter()
    cracked      = {}
    users_subset = list(salted_db.items())[:max_users]

    for username, (salt, stored_hash) in users_subset:
        for word in dictionary:
            if sha256(salt + word) == stored_hash:
                cracked[username] = word
                break

    return cracked, time.perf_counter() - start, len(users_subset)


def estimate_salted_work(num_users: int, dict_size: int,
                         hash_time_sec: float) -> dict:
    """Theoretical attacker work for the salted system."""
    return {
        "unsalted_W":          dict_size * hash_time_sec,
        "salted_W":            num_users * dict_size * hash_time_sec,
        "speedup_factor_N":    num_users,
        "salt_space_bits":     128,
        "exhaustive_W_years":  (2 ** 128) * dict_size * hash_time_sec
                               / (365.25 * 24 * 3600),
    }
