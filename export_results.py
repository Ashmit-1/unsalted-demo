"""
Export experiment results to CSV for PPT graphs.
"""

import csv


def export_to_csv(results: list, filename: str = "results.csv"):
    """
    Export results to CSV.

    Columns:
        test_id, num_users, dict_size, precompute_time,
        lookup_time, total_attack_time, cracked, success_rate
    """
    fieldnames = [
        "test_id",
        "num_users",
        "dict_size",
        "precompute_time",
        "lookup_time",
        "total_attack_time",
        "cracked",
        "success_rate",
    ]

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)

    print(f"\nResults exported to {filename}")
