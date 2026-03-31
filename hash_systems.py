"""
Password hashing systems — unsalted (vulnerable) and salted (secure).

Unsalted:  hash(password)                  — deterministic, rainbow-table crackable
Salted:    hash(salt ‖ password)           — unique 128-bit salt per user
"""

import os
from collections import Counter
from sha256_manual import sha256

# ── Unsalted (vulnerable) ────────────────────────────────────────────────────

def hash_database(users_dict: dict) -> tuple:
    """
    Hash all passwords without salt.

    Returns:
        (hashed_db, hash_frequency_map)
        hashed_db          : {username: hash_hex}
        hash_frequency_map : {hash_hex: count}  — reveals password reuse
    """
    hashed_db  = {}
    all_hashes = []

    for username, password in users_dict.items():
        h = sha256(password)
        hashed_db[username] = h
        all_hashes.append(h)

    return hashed_db, dict(Counter(all_hashes))


# ── Salted (secure) ──────────────────────────────────────────────────────────

SALT_BYTES = 16          # 128-bit salt space → 2¹²⁸ possible salts


def generate_salt() -> str:
    """Generate a cryptographically random hex salt."""
    return os.urandom(SALT_BYTES).hex()


def hash_password_salted(password: str, salt: str = None) -> tuple:
    """Hash password with a unique salt.  Returns (salt, hash_hex)."""
    if salt is None:
        salt = generate_salt()
    return salt, sha256(salt + password)


def hash_database_salted(users_dict: dict) -> dict:
    """
    Hash all passwords with unique per-user random salt.

    Returns:
        {username: (salt, hash_hex)}
    """
    return {
        username: hash_password_salted(password)
        for username, password in users_dict.items()
    }


def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    """Verify a login attempt against a stored (salt, hash) pair."""
    _, candidate = hash_password_salted(password, salt)
    return candidate == stored_hash


def get_salt_space_bits() -> int:
    return SALT_BYTES * 8
