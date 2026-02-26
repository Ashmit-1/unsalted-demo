"""
Simulate insecure (unsalted) password storage.
"""

from collections import Counter
from sha256_manual import sha256


def hash_database(users_dict: dict) -> tuple:
    """
    Hash all passwords without salt.

    Args:
        users_dict: {username: plaintext_password}

    Returns:
        (hashed_db, hash_frequency_map)
        hashed_db: {username: hash}
        hash_frequency_map: {hash: count} showing identical hash clustering
    """
    hashed_db = {}
    all_hashes = []

    for username, password in users_dict.items():
        h = sha256(password)
        hashed_db[username] = h
        all_hashes.append(h)

    hash_frequency_map = dict(Counter(all_hashes))

    return hashed_db, hash_frequency_map
