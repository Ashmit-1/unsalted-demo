"""
Simulate precomputation (rainbow table) + lookup attack on unsalted hashes.
"""

import time
from sha256_manual import sha256


def build_rainbow_table(dictionary: list) -> tuple:
    start = time.perf_counter()

    rainbow_table = {}
    for word in dictionary:
        h = sha256(word)
        rainbow_table[h] = word

    precompute_time = time.perf_counter() - start
    return rainbow_table, precompute_time

'''{
  hash("password"): "password",
  hash("123456"): "123456",
  hash("qwerty"): "qwerty"
}


hashed_db = {
  "user_0000": "5e884898...",
  "user_0001": "8d969eef..."
}


creack_db = {
  "user_0000": "password",
  "user_0001": "123456"
}
'''

def crack_database(hashed_db: dict, rainbow_table: dict) -> tuple:
    start = time.perf_counter()
    cracked = {}
    for username, h in hashed_db.items():
        if h in rainbow_table:
            cracked[username] = rainbow_table[h]

    lookup_time = time.perf_counter() - start
    return cracked, lookup_time
