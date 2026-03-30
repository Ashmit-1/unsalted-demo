"""
Prevention Mechanism: Salted password storage.

Each user's password is hashed with a unique cryptographically random salt.
This defeats precomputation (rainbow table) attacks entirely.

Mathematical argument:
  - Unsalted work: W = |D| × T_h  (one precomputation for all N users)
  - Salted work:   W = N × |D| × T_h  (must redo per user, salt invalidates table)
  - With 128-bit salt space S: W_effective = S × |D| × T_h  (astronomically large)
"""

import os
from collections import Counter
from sha256_manual import sha256

# Salt length in bytes — 16 bytes = 128-bit salt space of 2^128
SALT_BYTES = 16


def generate_salt() -> str:
    """Generate a cryptographically random hex salt."""
    return os.urandom(SALT_BYTES).hex()


def hash_password_salted(password: str, salt: str = None) -> tuple:
    """
    Hash a password with a unique salt.

    Returns:
        (salt, hash_hex)
    """
    if salt is None:
        salt = generate_salt()
    h = sha256(salt + password)
    return salt, h


def hash_database_salted(users_dict: dict) -> dict:
    """
    Hash all passwords WITH unique per-user random salt.

    Args:
        users_dict: {username: plaintext_password}

    Returns:
        salted_db: {username: (salt, hash)}
    """
    salted_db = {}
    for username, password in users_dict.items():
        salt, h = hash_password_salted(password)
        salted_db[username] = (salt, h)
    return salted_db


def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    """Verify a login attempt against a stored (salt, hash) pair."""
    _, candidate = hash_password_salted(password, salt)
    return candidate == stored_hash


def get_salt_space_bits() -> int:
    """Return the size of the salt space in bits."""
    return SALT_BYTES * 8
