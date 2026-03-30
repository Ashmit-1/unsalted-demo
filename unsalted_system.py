"""
Simulate insecure (unsalted) password storage.
"""

from collections import Counter
from sha256_manual import sha256


def hash_database(users_dict: dict) -> tuple:
    hashed_db = {}
    all_hashes = []

    for username, password in users_dict.items():
        h = sha256(password)
        hashed_db[username] = h
        all_hashes.append(h)

    hash_frequency_map = dict(Counter(all_hashes))

    return hashed_db, hash_frequency_map


'''
(
    {
        "user_0001": "HASH_A",
        "user_0002": "HASH_B",
        "user_0003": "HASH_A"
    },
    {
        "HASH_A": 2,
        "HASH_B": 1
    }
)
'''