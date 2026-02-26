"""
Centralized measurement and complexity validation.
"""


def calculate_success_rate(cracked_count: int, total_users: int) -> float:
    """Return success rate as a percentage."""
    if total_users == 0:
        return 0.0
    return (cracked_count / total_users) * 100


def estimate_work_unsalted(dict_size: int, hash_time: float) -> float:
    """
    Theoretical work: W = |D| * T_h
    where T_h is the average time to compute one hash.
    """
    return dict_size * hash_time


def log_results_to_dict(
    test_id: int,
    num_users: int,
    dict_size: int,
    precompute_time: float,
    lookup_time: float,
    total_attack_time: float,
    cracked: int,
    success_rate: float,
) -> dict:
    """Package a single test run's results into a dictionary."""
    return {
        "test_id": test_id,
        "num_users": num_users,
        "dict_size": dict_size,
        "precompute_time": precompute_time,
        "lookup_time": lookup_time,
        "total_attack_time": total_attack_time,
        "cracked": cracked,
        "success_rate": success_rate,
    }
