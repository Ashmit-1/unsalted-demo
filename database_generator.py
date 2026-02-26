"""
Generate controlled vulnerable user databases with configurable password reuse.
"""

import random
import string


def generate_dictionary(size: int) -> list:
    """
    Generate a password dictionary of the given size containing:
    - Common passwords (hard-coded)
    - Numeric patterns (0000-9999)
    - Random lowercase strings
    """
    common_passwords = [
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "1234567", "letmein", "trustno1", "dragon",
        "baseball", "iloveyou", "master", "sunshine", "ashley",
        "michael", "shadow", "123123", "654321", "superman",
        "qazwsx", "football", "password1", "password123", "welcome",
        "hello", "charlie", "donald", "login", "admin",
        "princess", "starwars", "solo", "passw0rd", "cheese",
        "summer", "winter", "spring", "autumn", "batman",
        "hunter", "killer", "pepper", "george", "access",
        "thunder", "matrix", "coffee", "chicken", "robert",
    ]

    dictionary = list(common_passwords)

    # Add numeric patterns
    for i in range(10000):
        if len(dictionary) >= size:
            break
        dictionary.append(f"{i:04d}")

    # Fill remaining with random lowercase strings
    while len(dictionary) < size:
        length = random.randint(6, 12)
        word = ''.join(random.choices(string.ascii_lowercase, k=length))
        dictionary.append(word)

    return dictionary[:size]


def generate_users(num_users: int, dictionary: list, reuse_probability: float = 0.7) -> dict:
    """
    Generate a user database where passwords are chosen from the dictionary.

    Args:
        num_users: Number of users to generate.
        dictionary: List of possible passwords.
        reuse_probability: Probability that a user picks from the top popular passwords.

    Returns:
        {username: plaintext_password}
    """
    # Define a "popular" subset (top 20% of dictionary)
    popular_count = max(1, len(dictionary) // 5)
    popular_passwords = dictionary[:popular_count]

    users = {}
    for i in range(num_users):
        username = f"user_{i:04d}"
        if random.random() < reuse_probability:
            password = random.choice(popular_passwords)
        else:
            password = random.choice(dictionary)
        users[username] = password

    return users
