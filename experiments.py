"""
Automated 25 test runs with randomized parameters.
"""

import random

from database_generator import generate_dictionary, generate_users
from hash_systems import hash_database
from attackers import build_rainbow_table, crack_database
from metrics import calculate_success_rate, log_results_to_dict


def run_test_suite(num_tests: int = 25, dict_base_size: int = 2000) -> list:
    
    full_dictionary = generate_dictionary(dict_base_size)

    results = []

    for i in range(num_tests):
        
        num_users = random.randint(50, 500)
        reuse_prob = round(random.uniform(0.5, 0.9), 2)
        dict_size = random.randint(len(full_dictionary) // 2, len(full_dictionary))
        dictionary = random.sample(full_dictionary, dict_size)

        # 1. Generate user database
        users = generate_users(num_users, dictionary, reuse_prob)

        # 2. Hash database (unsalted)
        hashed_db, hash_freq = hash_database(users)

        # 3. Build rainbow table (precomputation)
        rainbow_table, precompute_time = build_rainbow_table(dictionary)

        # 4. Attack
        cracked, lookup_time = crack_database(hashed_db, rainbow_table)

        total_attack_time = precompute_time + lookup_time
        cracked_count = len(cracked)
        success_rate = calculate_success_rate(cracked_count, num_users)

        result = log_results_to_dict(
            test_id=i + 1,
            num_users=num_users,
            dict_size=dict_size,
            precompute_time=precompute_time,
            lookup_time=lookup_time,
            total_attack_time=total_attack_time,
            cracked=cracked_count,
            success_rate=success_rate,
        )

        # Add hash clustering info
        result["hash_clusters"] = sum(1 for c in hash_freq.values() if c > 1)
        result["reuse_probability"] = reuse_prob

        results.append(result)

        print(f"Test {i + 1:2d}: Users={num_users:3d}  |D|={dict_size:4d}  "
              f"Cracked={cracked_count:3d}  Success={success_rate:5.1f}%  "
              f"Attack={total_attack_time:.4f}s")

    return results
