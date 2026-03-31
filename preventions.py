"""
Prevention mechanisms — Key Stretching and Salt + Pepper.

Stretched:  hash_0 = sha256(salt ‖ password),  hash_i = sha256(hash_{i-1})  i=1…K-1
Peppered:   hash   = sha256(pepper ‖ salt ‖ password)   pepper stored server-side only

Work complexity:
    Unsalted   W  =           |D| × T_h
    Salted     W  =       N × |D| × T_h
    Stretched  W  =   N × |D| × K × T_h       K = iterations
    Peppered   W  = |P| × N × |D| × T_h       |P| = 2²⁵⁶
"""

import os
import time
from sha256_manual import sha256

SALT_BYTES   = 16        # 128-bit salt, stored in DB
PEPPER_BYTES = 32        # 256-bit pepper, stored server-side ONLY
ITERATIONS   = 1_000     # K — stretch factor (reduce for demo speed)


# ════════════════════════════════════════════════════════════════════════════
# STRETCHED HASHING
# ════════════════════════════════════════════════════════════════════════════

def _stretch(salt: str, password: str, iterations: int) -> str:
    digest = sha256(salt + password)
    for _ in range(iterations - 1):
        digest = sha256(digest)
    return digest


def hash_password_stretched(password: str, salt: str = None,
                             iterations: int = ITERATIONS) -> tuple:
    """Return (salt, stretched_hash, iterations)."""
    if salt is None:
        salt = os.urandom(SALT_BYTES).hex()
    return salt, _stretch(salt, password, iterations), iterations


def hash_database_stretched(users_dict: dict, iterations: int = ITERATIONS,
                             log_cb=None) -> dict:
    """
    Hash all passwords with salt + key stretching.

    Returns:
        {username: (salt, hash, iterations)}
    """
    db    = {}
    total = len(users_dict)
    for idx, (username, password) in enumerate(users_dict.items(), 1):
        salt, h, itr = hash_password_stretched(password, iterations=iterations)
        db[username] = (salt, h, itr)
        if log_cb:
            log_cb(idx, total, username)
    return db


def verify_password_stretched(password: str, salt: str, stored_hash: str,
                               iterations: int = ITERATIONS) -> bool:
    return _stretch(salt, password, iterations) == stored_hash


def attempt_rainbow_on_stretched(stretched_db: dict,
                                  rainbow_table: dict) -> tuple:
    """
    Reuse a precomputed rainbow table against the stretched+salted DB.
    Fails: 0 % success (salt invalidates table; iterations irrelevant).
    """
    start   = time.perf_counter()
    cracked = {
        username: rainbow_table[h]
        for username, (salt, h, itr) in stretched_db.items()
        if h in rainbow_table
    }
    return cracked, time.perf_counter() - start


def estimate_stretched_work(num_users: int, dict_size: int,
                             hash_time: float,
                             iterations: int = ITERATIONS) -> dict:
    return {
        "unsalted_W":   dict_size * hash_time,
        "salted_W":     num_users * dict_size * hash_time,
        "stretched_W":  num_users * dict_size * iterations * hash_time,
        "K":            iterations,
        "K_factor":     iterations,
        "N_factor":     num_users,
        "total_factor": num_users * iterations,
    }


# ════════════════════════════════════════════════════════════════════════════
# PEPPERED HASHING
# ════════════════════════════════════════════════════════════════════════════

# Simulated server-side pepper — in production: loaded from env var / HSM
_SERVER_PEPPER: str = os.urandom(PEPPER_BYTES).hex()


def get_server_pepper() -> str:
    """Return the server's pepper (never written to DB)."""
    return _SERVER_PEPPER


def rotate_pepper() -> str:
    """Simulate pepper rotation (requires re-hashing all passwords)."""
    global _SERVER_PEPPER
    _SERVER_PEPPER = os.urandom(PEPPER_BYTES).hex()
    return _SERVER_PEPPER


def hash_password_peppered(password: str, salt: str = None,
                            pepper: str = None) -> tuple:
    """Hash with pepper ‖ salt ‖ password.  Returns (salt, hash_hex)."""
    if salt is None:
        salt = os.urandom(SALT_BYTES).hex()
    if pepper is None:
        pepper = get_server_pepper()
    return salt, sha256(pepper + salt + password)


def hash_database_peppered(users_dict: dict, pepper: str = None) -> dict:
    """
    Hash all passwords with pepper + unique salt.

    Returns:
        {username: (salt, hash_hex)}   — pepper absent from DB
    """
    if pepper is None:
        pepper = get_server_pepper()
    return {
        username: hash_password_peppered(password, pepper=pepper)
        for username, password in users_dict.items()
    }


def verify_password_peppered(password: str, salt: str, stored_hash: str,
                              pepper: str = None) -> bool:
    if pepper is None:
        pepper = get_server_pepper()
    _, candidate = hash_password_peppered(password, salt=salt, pepper=pepper)
    return candidate == stored_hash


def attempt_rainbow_on_peppered(peppered_db: dict,
                                 rainbow_table: dict) -> tuple:
    """
    Reuse standard rainbow table (built without pepper).
    Success: 0 % — table entries never match peppered hashes.
    """
    start   = time.perf_counter()
    cracked = {
        username: rainbow_table[h]
        for username, (salt, h) in peppered_db.items()
        if h in rainbow_table
    }
    return cracked, time.perf_counter() - start


def attempt_with_correct_pepper(peppered_db: dict, dictionary: list,
                                 pepper: str) -> tuple:
    """
    Simulated insider threat — attacker has DB + pepper.
    Degrades to per-user dictionary attack identical to salted case.
    """
    start   = time.perf_counter()
    cracked = {}
    for username, (salt, stored_hash) in peppered_db.items():
        for word in dictionary:
            if sha256(pepper + salt + word) == stored_hash:
                cracked[username] = word
                break
    return cracked, time.perf_counter() - start


def estimate_peppered_work(num_users: int, dict_size: int,
                            hash_time: float,
                            pepper_bits: int = 256) -> dict:
    peppered = (2 ** pepper_bits) * num_users * dict_size * hash_time
    return {
        "unsalted_W":     dict_size * hash_time,
        "salted_W":       num_users * dict_size * hash_time,
        "peppered_W":     peppered,
        "peppered_years": peppered / (365.25 * 24 * 3600),
        "pepper_bits":    pepper_bits,
        "pepper_factor":  2 ** pepper_bits,
    }
