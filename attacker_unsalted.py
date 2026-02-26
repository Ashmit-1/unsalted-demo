"""
Simulate precomputation (rainbow table) + lookup attack on unsalted hashes.
"""

import time
from sha256_manual import sha256


def build_rainbow_table(dictionary: list) -> tuple:
    """
    Precompute hashes for every word in the dictionary.

    Returns:
        (rainbow_table, precompute_time)
        rainbow_table: {hash: password}
        precompute_time: seconds taken
    """
    start = time.perf_counter()

    rainbow_table = {}
    for word in dictionary:
        h = sha256(word)
        rainbow_table[h] = word

    precompute_time = time.perf_counter() - start
    return rainbow_table, precompute_time


def crack_database(hashed_db: dict, rainbow_table: dict) -> tuple:
    """
    Look up each hashed password in the rainbow table.

    Returns:
        (cracked, lookup_time)
        cracked: {username: recovered_password}
        lookup_time: seconds taken for the lookup phase
    """
    start = time.perf_counter()

    cracked = {}
    for username, h in hashed_db.items():
        if h in rainbow_table:
            cracked[username] = rainbow_table[h]

    lookup_time = time.perf_counter() - start
    return cracked, lookup_time
