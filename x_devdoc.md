# Password Hash Attack & Prevention — Developer Documentation

> This document explains everything you built: what each file does, what every function does, what every constant means, what every formula means (terms fully defined), and a detailed walkthrough of every GUI feature. Read this once and you will know exactly how this system works.

---

## Table of Contents

1. [What This Project Is](#1-what-this-project-is)
2. [Project Structure](#2-project-structure)
3. [Dependency Graph](#3-dependency-graph)
4. [Constants & Terms Glossary](#4-constants--terms-glossary)
5. [File-by-File Breakdown](#5-file-by-file-breakdown)
   - [sha256_manual.py](#sha256_manualpy)
   - [database_generator.py](#database_generatorpy)
   - [hash_systems.py](#hash_systemspy)
   - [preventions.py](#preventionspy)
   - [attackers.py](#attackerspy)
   - [metrics.py](#metricspy)
   - [export_results.py](#export_resultspy)
   - [comparison_runner.py](#comparison_runnerpy)
   - [main.py](#mainpy)
   - [gui.py](#guipy)
6. [Work Complexity Formulas — Terms Explained](#6-work-complexity-formulas--terms-explained)
7. [GUI Features — Detailed Walkthrough](#7-gui-features--detailed-walkthrough)
8. [Data Flow End-to-End](#8-data-flow-end-to-end)

---

## 1. What This Project Is

This is an **interactive educational tool** that demonstrates, side-by-side, why plain SHA-256 password hashing is dangerous and how three defensive techniques progressively eliminate attacker leverage.

Four hashing systems are compared:

| System | What it stores | Attacker's job |
|---|---|---|
| **Unsalted SHA-256** | `sha256(password)` | Build one table, crack everyone instantly |
| **Salted SHA-256** | `sha256(salt ‖ password)` | Must redo work per user — table useless |
| **Key-Stretched** | `sha256` applied `K` times | Same as salted, but `K×` more compute per guess |
| **Salt + Pepper** | `sha256(pepper ‖ salt ‖ password)` | Salt + a secret only on the server — `2²⁵⁶` harder |

The GUI runs real attacks and real defences against real dictionaries, measures success rates, and visualises everything live.

---

## 2. Project Structure

```
crypto/
├── sha256_manual.py       # Pure-Python SHA-256 implementation
├── database_generator.py  # Fake user database factory
├── hash_systems.py        # Unsalted + salted hashing
├── preventions.py         # Key-stretching + pepper hashing
├── attackers.py           # Rainbow table builder + attack functions
├── metrics.py             # Success rate + work estimation helpers
├── export_results.py      # CSV export
├── comparison_runner.py   # Four-way experiment orchestrator
├── main.py                # CLI entry point
└── gui.py                 # Full CustomTkinter GUI
```

---

## 3. Dependency Graph

```
gui.py
 ├── comparison_runner.py
 │    ├── database_generator.py
 │    ├── hash_systems.py  ──────┐
 │    ├── preventions.py         │
 │    ├── attackers.py           │──→  sha256_manual.py
 │    └── metrics.py             │
 ├── hash_systems.py  ───────────┘
 ├── preventions.py
 ├── attackers.py
 ├── metrics.py
 └── export_results.py

main.py
 ├── comparison_runner.py
 ├── export_results.py
 └── metrics.py
```

`sha256_manual.py` is the only leaf — everything else builds on top of it.

---

## 4. Constants & Terms Glossary

Every variable name that appears in formulas or code, defined plainly:

| Symbol / Name | Where defined | What it means |
|---|---|---|
| `\|D\|` / `dict_size` | `database_generator.py`, `comparison_runner.py` | Number of passwords in the attacker's dictionary |
| `N` / `num_users` | `comparison_runner.py`, GUI inputs | Number of user accounts in the target database |
| `T_h` / `hash_time` | `comparison_runner.py` | Time in seconds to compute **one** SHA-256 hash. Measured as `precompute_time / dict_size` |
| `K` / `ITERATIONS` / `k_iter` | `preventions.py` (default `1_000`), GUI K-slider | Number of times SHA-256 is applied during key-stretching. Each additional round multiplies attacker cost by 1 |
| `W` | All formula comments | **Work** — total compute cost for the attacker to crack passwords |
| `SR` / `success_rate` | `metrics.py` | Percentage of user accounts the attacker successfully cracked |
| `SALT_BYTES` | `hash_systems.py`, `preventions.py` → `16` | Number of random bytes in a salt = 16 bytes = 128 bits → `2¹²⁸` possible salts |
| `PEPPER_BYTES` | `preventions.py` → `32` | Number of bytes in the server-side pepper = 32 bytes = 256 bits → `2²⁵⁶` possible peppers |
| `reuse_probability` | `database_generator.py` | Fraction of users that pick from the most popular 20% of passwords. Default 0.7 = 70% |
| `popular_count` | `database_generator.py` | Top 20% of dictionary = `max(1, len(dict) // 5)` passwords treated as "commonly reused" |
| `rt` / rainbow table | `attackers.py` | Python dict `{sha256(word): word}` — reverse lookup from hash back to plaintext |
| `pre_t` / `precompute_time` | `attackers.py` | Wall-clock seconds to build the rainbow table |
| `lk_t` / `lookup_time` | `attackers.py` | Wall-clock seconds to do all hash lookups (negligible — O(1) per user) |
| `‖` | Everywhere in comments | String concatenation. `salt ‖ password` means `salt + password` in Python |
| `_SERVER_PEPPER` | `preventions.py` | A module-level variable holding the pepper. Generated once with `os.urandom(32)`. Never written to any DB |
| `H_INIT` | `sha256_manual.py` | The 8 initial hash state values for SHA-256 (first 32 bits of fractional parts of √2, √3, √5, …√19) |
| `K` (sha256 constant) | `sha256_manual.py` | 64 round constants (first 32 bits of ∛2, ∛3, … ∛311) — **different K from stretch iterations** |
| `NUM_ROUNDS` | `sha256_manual.py` → `64` | How many compression rounds SHA-256 performs per 512-bit block |
| `MASK` | `sha256_manual.py` → `0xffffffff` | Keeps all arithmetic within 32 bits (simulates hardware overflow) |

---

## 5. File-by-File Breakdown

---

### `sha256_manual.py`

**Purpose:** A complete, from-scratch SHA-256 implementation in pure Python. No `hashlib`. Used everywhere instead of the standard library so the project is self-contained and educational.

**Why it matters:** Every hash in the project goes through this file. Performance is slower than `hashlib` — this is intentional: it makes the time measurements meaningful and the K-stretch overhead visible.

---

#### Helper bit operations

```python
MASK = 0xffffffff
```
Since Python integers are unlimited precision, `& MASK` after every operation keeps values at exactly 32 bits — the same as a C `uint32_t`.

```python
def rotr(x, n)
```
Rotate-right: shifts bits `n` positions to the right, and the bits that fall off the right end reappear at the left.
- Formula: `(x >> n) | (x << (32 - n)) & MASK`
- Used in the SHA-256 sigma functions.

```python
def shr(x, n)
```
Plain right-shift. Bits that fall off the right are discarded (no wrap).

```python
def ch(x, y, z)   # "Choose"
```
For each bit position: if `x`'s bit is 1, the output bit comes from `y`; if 0, it comes from `z`.
- Formula: `(x & y) ^ (~x & z) & MASK`

```python
def maj(x, y, z)  # "Majority"
```
For each bit position: the output bit is whatever value appears in at least 2 of the 3 inputs.
- Formula: `(x & y) ^ (x & z) ^ (y & z)`

```python
def sigma0(x)   # lowercase σ₀  — used in message schedule
def sigma1(x)   # lowercase σ₁  — used in message schedule
def Sigma0(x)   # uppercase Σ₀  — used in compression function
def Sigma1(x)   # uppercase Σ₁  — used in compression function
```
These are fixed mixtures of rotate-right and shift-right operations that give SHA-256 its avalanche effect (a 1-bit change in input scrambles the output unpredictably).

---

#### `pad_message(message: bytes) → bytes`

SHA-256 processes data in 512-bit (64-byte) chunks. Messages are almost never exactly that length, so padding is added:
1. Append a `0x80` byte (a `1` bit followed by zeros).
2. Append `0x00` bytes until the total length is `56 mod 64`.
3. Append the **original** message length as an 8-byte big-endian integer.

This ensures the last block is complete and the original length is encoded in the hash.

---

#### `process_block(block: bytes, h_state: list, num_rounds=64) → list`

Processes one 512-bit block. This is the SHA-256 **compression function**.

Steps:
1. **Message schedule**: expand the 16 × 32-bit words in the block into 64 words using `sigma0` / `sigma1`.
2. **Compression loop**: 64 rounds of mixing using `ch`, `maj`, `Sigma0`, `Sigma1`, round constants `K[i]`, and scheduled words.
3. **Add back**: each of the 8 working variables is added back to the corresponding `h_state` element (mod 2³²). This is the **Davies-Meyer** construction — previous state feeds into next block.

---

#### `sha256(message: str, num_rounds=64) → str`

Public entry point. Takes a plain Python string, encodes it to UTF-8, pads it, processes every 64-byte block, and returns a 64-character lowercase hex string.

---

### `database_generator.py`

**Purpose:** Generate fake but realistic user databases for experiments. Controls password reuse — the key variable that determines how badly unsalted hashing performs.

---

#### `generate_dictionary(size: int) → list`

Builds the attacker's wordlist of `size` passwords:
1. Starts with 50 hardcoded common passwords (`"password"`, `"123456"`, etc.)
2. Fills up to 10,000 entries with 4-digit numeric patterns (`"0000"` through `"9999"`)
3. Fills remaining slots with random 6–12 character lowercase strings

Returns a list of exactly `size` strings. This list is used both as the attacker's dictionary and as the pool users draw passwords from.

---

#### `generate_users(num_users, dictionary, reuse_probability=0.7) → dict`

Returns `{"user_0001": "password", "user_0002": "dragon", ...}`.

The `reuse_probability` parameter controls clustering:
- `popular_count = max(1, len(dictionary) // 5)` — the top 20% of the dictionary is the "popular" bucket.
- With probability `reuse_probability` (default 0.7), a user picks from the popular bucket.
- Otherwise they pick from the full dictionary.

**Why this matters:** If 70% of users pick from only 20% of passwords, many users share the same hash in the unsalted database. Cracking one hash exposes multiple accounts. The salted database is immune to this clustering because identical passwords hash to different values.

---

### `hash_systems.py`

**Purpose:** The two basic hashing systems — vulnerable unsalted and baseline salted.

---

#### `SALT_BYTES = 16`

16 bytes = 128 bits. Each salt is `os.urandom(16).hex()` — a 32-character hex string drawn from `2¹²⁸` possible values. An attacker who wants to precompute a rainbow table for a salted database would need to store `2¹²⁸` tables — impossible.

---

#### `hash_database(users_dict) → (hashed_db, hash_frequency_map)`

Unsalted hashing. Applies `sha256(password)` for every user. Returns:
- `hashed_db`: `{username: hash_hex}` — what an unsalted database looks like after a breach
- `hash_frequency_map`: `{hash_hex: count}` — a Counter that exposes password reuse. If 50 users share `"password"`, all 50 appear under the same hash key with count 50.

---

#### `generate_salt() → str`

`os.urandom(16).hex()` — cryptographically random, 128-bit salt as a hex string.

---

#### `hash_password_salted(password, salt=None) → (salt, hash_hex)`

Produces `sha256(salt + password)`. If no salt is given, generates a fresh one. The salt is stored alongside the hash in the database.

---

#### `hash_database_salted(users_dict) → {username: (salt, hash_hex)}`

Applies `hash_password_salted` to every user with a fresh random salt each time. Even if two users have identical passwords, their stored records look completely different.

---

#### `verify_password(password, salt, stored_hash) → bool`

Login check: recomputes `sha256(salt + password)` and compares to the stored hash. This is how a server validates a login without storing the plaintext.

---

#### `get_salt_space_bits() → int`

Returns `128`. Used in comments and log output.

---

### `preventions.py`

**Purpose:** The two advanced defences — key-stretching and pepper. Both build on top of salted hashing.

---

#### `SALT_BYTES = 16`, `PEPPER_BYTES = 32`, `ITERATIONS = 1_000`

- `SALT_BYTES`: same 128-bit salt as before — stored in DB.
- `PEPPER_BYTES`: 256-bit pepper — **never stored**, server-side only.
- `ITERATIONS` (`K`): how many rounds of SHA-256 to apply. Default 1,000. The GUI slider lets you change this live.

---

#### Key-Stretching

```python
def _stretch(salt, password, iterations) → str
```

Internal engine. Computes:
```
h₀ = sha256(salt ‖ password)
h₁ = sha256(h₀)
h₂ = sha256(h₁)
...
h_{K-1} = sha256(h_{K-2})
```
Returns `h_{K-1}`. This is a simplified version of PBKDF2.

Every guess the attacker makes costs `K` hash computations instead of 1. If `K = 1000`, cracking is `1000×` slower. For legitimate login this adds only a few milliseconds. For an attacker guessing billions of passwords it is devastating.

---

#### `hash_password_stretched(password, salt=None, iterations=ITERATIONS) → (salt, hash, iterations)`

Public wrapper around `_stretch`. Generates a salt if none given. Returns all three values so the DB can store `(salt, hash, K)`.

---

#### `hash_database_stretched(users_dict, iterations, log_cb=None) → {username: (salt, hash, iterations)}`

Hashes every user with key-stretching. Optionally calls `log_cb(idx, total, username)` after each user so the GUI can show progress.

---

#### `verify_password_stretched(password, salt, stored_hash, iterations) → bool`

Login check: recomputes the full stretch chain and compares. The `iterations` value stored with each hash is used so the K parameter can change over time.

---

#### `attempt_rainbow_on_stretched(stretched_db, rainbow_table) → (cracked_dict, elapsed)`

Tries to look up every stretched hash in the standard rainbow table. Succeeds 0% of the time — the salt alone makes the table entries wrong (stretching is irrelevant to why it fails).

---

#### `estimate_stretched_work(num_users, dict_size, hash_time, iterations) → dict`

Returns a breakdown of theoretical work:
- `stretched_W = N × |D| × K × T_h` — total seconds to brute-force all users
- `K_factor` = `K` — stretch multiplier
- `N_factor` = `N` — per-user multiplier
- `total_factor` = `N × K`

---

#### Pepper

```python
_SERVER_PEPPER: str = os.urandom(PEPPER_BYTES).hex()
```

A module-level constant generated once when the module is imported. In production this would come from an environment variable or HSM. It is **never written to the database**.

---

#### `get_server_pepper() → str`

Returns the current pepper. Called by hashing and verification functions.

---

#### `rotate_pepper() → str`

Simulates a pepper rotation event (e.g. after a suspected server compromise). Generates a new random pepper. In production this would require re-hashing every password.

---

#### `hash_password_peppered(password, salt=None, pepper=None) → (salt, hash_hex)`

Computes `sha256(pepper ‖ salt ‖ password)`. The pepper is prepended first so it cannot be stripped even if the attacker knows the salt. The salt is still stored in the DB; the pepper is not.

---

#### `hash_database_peppered(users_dict, pepper=None) → {username: (salt, hash_hex)}`

Hashes every user with the pepper + a unique salt. The DB record stores `(salt, hash)`. The pepper is absent from every record.

---

#### `attempt_rainbow_on_peppered(peppered_db, rainbow_table) → (cracked_dict, elapsed)`

Tries the standard rainbow table against peppered hashes. 0% success — the secret pepper is not in the table entries.

---

#### `attempt_with_correct_pepper(peppered_db, dictionary, pepper) → (cracked_dict, elapsed)`

Simulates an insider threat where the attacker has both the DB dump **and** the server pepper. With the pepper known, security degrades to the salted case: `O(N × |D| × T_h)`. This function is used to demonstrate that the pepper is not magic — it only helps if the server is not compromised.

---

#### `estimate_peppered_work(num_users, dict_size, hash_time, pepper_bits=256) → dict`

Computes:
- `peppered_W = 2^pepper_bits × N × |D| × T_h`
- `peppered_years = peppered_W / seconds_per_year`
- `pepper_factor = 2^256 ≈ 1.16 × 10⁷⁷`

---

### `attackers.py`

**Purpose:** All the attack code. Builds the rainbow table and executes attacks against each type of database.

---

#### `build_rainbow_table(dictionary) → (table, precompute_time)`

Hashes every word in the dictionary once:
```python
table = {sha256(word): word for word in dictionary}
```
Returns the reverse-lookup dict and how long it took.

**Cost:** `O(|D|)` — paid once. Then any number of users can be cracked for free.

---

#### `crack_database(hashed_db, rainbow_table) → (cracked_dict, lookup_time)`

For every user in the unsalted database, looks up their hash in the table:
```python
cracked = {username: table[h] for username, h in hashed_db.items() if h in table}
```
**Cost:** `O(N)` lookups, each `O(1)` (Python dict). Total: `O(N)` after the table exists.

---

#### `attempt_rainbow_on_salted(salted_db, rainbow_table) → (cracked_dict, elapsed)`

Tries the same lookup against salted hashes. The stored hashes are `sha256(salt + password)` — these are not in a table built from `sha256(password)`. Result: 0 cracked.

---

#### `bruteforce_salted(salted_db, dictionary, max_users=15) → (cracked_dict, elapsed, count)`

For each user (up to `max_users`), tries every word in the dictionary:
```python
for word in dictionary:
    if sha256(salt + word) == stored_hash:
        cracked[username] = word; break
```
**Cost:** `O(max_users × |D| × T_h)`. Capped at 15 users for demo speed. This shows that salted cracking **can** be done — it just costs N× more than unsalted.

---

#### `estimate_salted_work(num_users, dict_size, hash_time_sec) → dict`

Returns:
- `unsalted_W = |D| × T_h`
- `salted_W = N × |D| × T_h`
- `speedup_factor_N = N` — how many times harder salted is vs unsalted
- `exhaustive_W_years` — time to exhaustively try all `2¹²⁸` salts (practically infinite)

---

### `metrics.py`

**Purpose:** Centralized measurement helpers. Keeps calculation logic out of the runner and GUI.

---

#### `calculate_success_rate(cracked_count, total_users) → float`

```
SR = (cracked / total) × 100
```
Returns a percentage. If `total_users = 0`, returns `0.0` (guard against division by zero).

---

#### `estimate_work_unsalted(dict_size, hash_time) → float`

Returns `|D| × T_h` — theoretical time to build the rainbow table. Used to verify that measured precompute times match theory.

---

#### `log_results_to_dict(...) → dict`

Packages one test run's numbers into a dict for storage and CSV export. Fields:
- `test_id`, `num_users`, `dict_size`
- `precompute_time` — time to build the rainbow table
- `lookup_time` — time to do all hash lookups
- `total_attack_time` — sum of both
- `cracked` — count of successfully cracked accounts
- `success_rate` — percentage cracked

---

### `export_results.py`

**Purpose:** Write experiment results to a CSV file for external analysis or presentations.

---

#### `export_to_csv(results, filename="results.csv")`

Writes a list of result dicts to CSV. The columns are:
`test_id`, `num_users`, `dict_size`, `precompute_time`, `lookup_time`, `total_attack_time`, `cracked`, `success_rate`.

Uses `extrasaction="ignore"` so extra keys in result dicts don't cause errors.

---

### `comparison_runner.py`

**Purpose:** The experiment engine. Runs N paired tests comparing all four hashing systems under randomised conditions, then produces a final summary report.

---

#### `run_full_comparison(num_tests, dict_base_size, k_iter, log_cb, progress_cb, stop_event, test_cb) → dict`

Main entry point called by the GUI's "Run Full Comparison" button. Parameters:

| Parameter | What it controls |
|---|---|
| `num_tests` | How many paired test rounds to run (default 25) |
| `dict_base_size` | Maximum dictionary size (default 2000). Each test samples a random subset |
| `k_iter` | K value for key-stretching (taken from GUI K-slider) |
| `log_cb` | Callback `(message, tag)` — posts each log line to the GUI text widget |
| `progress_cb` | Callback `(percent)` — drives the GUI progress bar |
| `stop_event` | `threading.Event` — if set, loop exits early (STOP button) |
| `test_cb` | Callback `(u_sr, s_sr, st_sr, p_sr)` — fired after each test, feeds the live graph |

**Each test round does:**
1. Randomise `num_users` (50–500), `reuse_prob` (50–90%), `dict_size` (half to full of base size)
2. Build one shared rainbow table
3. Hash the user DB four ways (unsalted, salted, stretched, peppered)
4. Attack each hashed DB with the same rainbow table
5. Compute `SR` for each, log work formulas, call `test_cb`

**Returns** a dict with keys `"unsalted"`, `"salted"`, `"stretched"`, `"peppered"` (each a list of per-test result dicts) plus `"summary"`.

---

#### `_summarise(results) → dict`

Computes averages across all tests: `avg_unsalted_sr`, `avg_salted_sr`, `avg_stretched_sr`, `avg_peppered_sr`, `avg_*_time`, `tests_ge90`, `K_iterations`.

---

#### `_log_final(log, summary)`

Prints the final comparative table and the recommendation block (use salt + key-stretching + pepper + Argon2id/bcrypt in production).

---

### `main.py`

**Purpose:** CLI entry point for running the experiments without the GUI.

Runs two phases:
1. **Unsalted baseline** — 25 tests, records and prints attack success rates and times.
2. **Comparative analysis** — 25 paired tests, prints per-test unsalted vs salted, then a summary.
3. **Mathematical validation** — prints predicted W vs measured precompute time for the first 10 tests.
4. **Independence of N** — groups tests by small N (≤150) and large N (≥350), shows attack time barely changes for the unsalted system (proving it is O(|D|), not O(N)).
5. Exports both CSVs.

---

### `gui.py`

**Purpose:** The complete application UI. See Section 7 for each feature. Below are the structural pieces.

---

#### Colour palette constants

```python
BK   = "#000000"   # background black
WH   = "#ffffff"   # primary white text
GRN  = "#22c55e"   # success / secure green
RED  = "#ef4444"   # attack / vulnerable red
AMB  = "#f59e0b"   # amber — hash values
BLU  = "#60a5fa"   # info blue
MID  = "#6b7280"   # muted grey
DIM  = "#374151"   # very dark grey
PNL  = "#111111"   # panel background
MONO = "Courier"   # monospace font for all text
```

---

#### `class App(ctk.CTk)`

The main window. Key instance variables:

| Variable | Type | What it holds |
|---|---|---|
| `self.vn` | `StringVar` | "Num Users" input field value |
| `self.vd` | `StringVar` | "Dict Size" input field value |
| `self.vt` | `StringVar` | "Num Tests" input field value |
| `self.vr` | `DoubleVar` | "Reuse Probability" slider value (0.0–1.0) |
| `self._k_val` | `int` | Current K (stretch iterations), controlled by K-slider |
| `self._stop` | `threading.Event` | Set by STOP button to interrupt a running experiment |
| `self._results` | `dict or None` | Holds the last `run_full_comparison` result for export/graphs |
| `self._live_u` | `list` | Per-test unsalted success rates, for the live graph |
| `self._live_d` | `list` | Per-test defence average success rates, for the live graph |
| `self._sv` | `dict` | Label widgets in the STATS panel, keyed by system name |

---

## 6. Work Complexity Formulas — Terms Explained

### Unsalted

```
W = |D| × T_h
```

- `|D|` — number of passwords in the dictionary (e.g. 2,000)
- `T_h` — time per single SHA-256 hash (measured, typically ~0.001–0.01 s in pure Python)
- **W** = total time to build the rainbow table
- After the table is built, cracking every user costs `O(1)` per lookup. N does not appear in the formula. Whether the DB has 10 or 10,000 users, the attack cost is the same.

### Salted

```
W = N × |D| × T_h
```

- `N` — number of users the attacker wants to crack
- The rainbow table is useless. For each user, the attacker must try every dictionary word with that user's specific salt.
- **W grows linearly with N** — the first user costs `|D| × T_h`, the second costs the same, and so on.

### Key-Stretched

```
W = N × |D| × K × T_h
```

- `K` — stretch iterations. Every dictionary guess now costs `K` hashes instead of 1.
- Legitimate login: the server does `K` hashes once per login. At `K = 1000` and `T_h = 0.001s`, login adds ~1 ms overhead. Acceptable.
- Attacker with `|D| = 2000` guesses per user: `2000 × 1000 = 2,000,000` hashes per user. At the same `T_h`, that's 2,000 seconds (~33 minutes) per user. For N = 100 users: 3,300 minutes.
- Increasing K is free for the defender (a config change), expensive for the attacker.

### Peppered

```
W = 2²⁵⁶ × N × |D| × T_h
```

- `2²⁵⁶` — the pepper keyspace. The attacker does not know the 256-bit pepper. To crack a single hash they would need to try every possible pepper for every dictionary word.
- `2²⁵⁶ ≈ 1.16 × 10⁷⁷`. At 10¹⁸ hashes/second (faster than any computer): `10⁷⁷ / 10¹⁸ = 10⁵⁹` seconds — orders of magnitude longer than the age of the universe.
- **Caveat:** if an attacker gets both the DB and the server (insider threat), the pepper is known and security falls back to the salted case.

### Success Rate

```
SR = (cracked / N) × 100
```

- `cracked` — number of accounts successfully recovered
- `N` — total accounts in the test
- Reported as a percentage. For unsalted: typically 80–100%. For all three defences: 0%.

---

## 7. GUI Features — Detailed Walkthrough

---

### Sidebar Controls

The left sidebar has four input fields and a slider:

| Control | Variable | Effect |
|---|---|---|
| Num Users | `vn` | How many fake user accounts per test |
| Dict Size | `vd` | Size of the attacker's dictionary |
| Num Tests | `vt` | How many test rounds `run_full_comparison` runs |
| Reuse % | `vr` | Password reuse probability (0–1 slider) |
| Stretch K | `_k_val` | Key-stretch iteration count, fed to `run_full_comparison` as `k_iter` |

The K slider label shows `K = 10 → ×10 per guess`, updating dynamically as the slider moves.

---

### Action Buttons

Eight buttons in the Actions panel. All long-running ones fire in a `threading.Thread` so the GUI stays responsive.

---

### Feature: Run Attack (Unsalted Only)

Button: **run attack**

What it does:
1. Reads `dict_size` and `num_tests` from inputs.
2. Generates a dictionary and users (uses default reuse prob).
3. Builds a rainbow table.
4. Hashes the user DB without salt.
5. Cracks the hashed DB with the table.
6. Logs attack timing and success rate to the log widget.
7. Updates the `unsalted` stat label.

Purpose: Quick demo of the unsalted vulnerability alone, without running the full four-way comparison.

---

### Feature: Run Full Comparison

Button: **run full comparison**

What it does:
1. Spawns a background thread calling `run_full_comparison(...)` with all GUI parameters.
2. Each test fires `test_cb(u_sr, s_sr, st_sr, p_sr)` which appends to `_live_u` and `_live_d` for the live graph.
3. After each test the progress bar advances.
4. When done, updates all four STATS labels (unsalted in red, the three defences in green).
5. Stores full results in `self._results` for export and graph access.

The STOP button sets `self._stop` which the runner checks between tests.

---

### Feature: Apply Prevention

Button: **apply prevention**

What it does:
- Logs the banner and full mathematical proof of all four work formulas.
- Shows exact values: `K`, `N`, `|D|`, salt space (2¹²⁸), pepper space (2²⁵⁶).
- Prints the recommendation block from `_log_final`.

This is a static educational display — no computation runs.

---

### Feature: Show Graphs

Button: **show graphs**

What it does:
1. Checks `self._results` is not None (requires a completed full comparison).
2. Opens a `CTkToplevel` window with a `matplotlib` figure embedded.
3. Draws two subplots:
   - **Left:** Bar chart of average success rates for all four systems.
   - **Right:** Per-test line chart — unsalted SR (red) vs defence average SR (green), with a shaded fill between them showing the security gap.
4. Uses the project's colour palette (black background, green/red lines).

---

### Feature: Breach Simulator

Button: **breach simulator**

What it does step-by-step:
1. Generates a tiny database: 10-word dictionary, 30 users, 95% reuse probability (maximises clustering).
2. Hashes the users two ways: unsalted (`hash_database`) and salted (`hash_database_salted`).
3. Opens a `CTkToplevel` with two panels side-by-side:

**Left panel — Unsalted breach:**
- Lists every user, their hash (first 20 chars), and a status indicator.
- Groups users by hash — users sharing a password are highlighted together.
- Shows a `freq` map: e.g. `"abc123" → 8 accounts`. These all show as the same hash.
- Demonstrates visually that one cracked hash = multiple compromised accounts.

**Right panel — Salted breach:**
- Lists every user, their salt (first 12 chars), their hash (first 20 chars), and `UNIQUE ✔`.
- Even users with identical passwords have completely different records.
- The attacker sees no clustering. Each account must be attacked individually.

**Footer:** Shows `"Unsalted: X shared hashes | Salted: 0 shared hashes"` as a one-line summary.

**Educational point:** The breach simulator exists to make the reuse problem tangible. You can see the same hash repeated 8 times in the unsalted panel. In the salted panel every row looks different.

---

### Feature: Live Crack Demo

Button: **live crack demo**

This is a two-step interactive demo:

**Step 1 — Password entry popup**
- A small 540×160 window appears with a title `"LIVE CRACK DEMO"`.
- The professor/user types any password into the entry field.
- Pressing Enter or clicking ATTACK closes this window and starts the demo.

**Step 2 — Animated demo window**
- A 900×600 scrolling text window opens with the title `"LIVE ATTACK DEMO"`.
- Text appears line-by-line with timed delays using `win.after(ms, ...)` — gives a "live hacking" feel.
- Five phases play out in sequence:

**Phase 1 — Build the Rainbow Table**
- Shows dictionary size and how long it took to build.
- Explains O(1) lookup cost.

**Phase 2 — Attack on Unsalted Database**
- Shows the victim's stored hash (`sha256(password)`).
- Scrolls through 5 sample table entries to show the table structure.
- Simulates the table lookup with a delay, then reveals the cracked password in red bold.
- `CRACKED in < 1 ms` — one dict lookup.

**Phase 3 — Same Attack on Salted Database**
- Shows the unique salt and the salted hash (`sha256(salt ‖ password)`).
- Simulates the lookup — gets `KeyError — NOT IN TABLE`.
- Shows `SECURE` in green.
- Explains: attacker must now compute `sha256(salt ‖ w)` for every `w` — O(N × |D|).

**Phase 4 — Key-Stretched Database**
- Shows the salt, the K value (taken from GUI slider), and the stretched hash.
- Same table lookup — fails.
- Explains: each guess now costs `K` hashes, not 1. Work multiplied by `K`.

**Phase 5 — Peppered Database**
- Notes pepper is secret (server-side only, never in DB).
- Shows salt and peppered hash.
- Same table lookup — fails.
- Explains: attacker must brute-force `2²⁵⁶` pepper values. Computationally infeasible.

**Verdict**
- Four-line summary showing each system's result.
- Restates the table build cost and that it cracks every unsalted account forever at zero marginal cost.

All text is coloured: red for attacks/vulnerable, green for secure, amber for hashes, purple for headers.

---

### Feature: Export CSV

Button: **export csv**

What it does:
1. Opens a file save dialog.
2. Zips the four result lists (unsalted, salted, stretched, peppered) together.
3. Writes one row per test with columns: `test_id`, `num_users`, `dict_size`, `unsalted_sr_%`, `salted_sr_%`, `stretched_sr_%`, `peppered_sr_%`, `unsalted_time_s`.

Requires a completed full comparison (`self._results` not None).

---

### Feature: Clear Log

Button: **clear log**

Deletes all text from the main log widget and re-prints the startup banner.

---

### STATS Panel

Four labels in the right sidebar: **unsalted**, **salted**, **stretched**, **peppered**. After a full comparison completes, each updates to show `avg_sr%`. Unsalted is red; the three defences are green.

---

### Live Graph (inside main window)

At the bottom of the right panel, a small embedded `matplotlib` canvas shows two lines that update after each test during a full comparison:
- **Red line** (`_live_u`): unsalted success rate per test
- **Green line** (`_live_d`): defence average success rate per test
- Shaded area between them shows the security gap growing (or confirmed stable) across tests.

The "show graphs" button opens a full-size version of this with both subplots.

---

## 8. Data Flow End-to-End

```
User clicks "run full comparison"
        │
        ▼
gui.py _run_full() spawns Thread
        │
        ▼
comparison_runner.run_full_comparison()
        │
        ├─ database_generator.generate_dictionary(dict_base_size)
        │       └─ returns list of passwords (attacker wordlist + user pool)
        │
        ├─ for each test:
        │   ├─ generate_users(N, dictionary, reuse_prob)
        │   │       └─ returns {username: password}
        │   │
        │   ├─ attackers.build_rainbow_table(dictionary)
        │   │       └─ {sha256(w): w for w in dictionary}  via sha256_manual.sha256
        │   │
        │   ├─ hash_systems.hash_database(users)
        │   │       └─ {username: sha256(password)}
        │   ├─ attackers.crack_database(hdb, rt)
        │   │       └─ {username: password} for matches
        │   │
        │   ├─ hash_systems.hash_database_salted(users)
        │   │       └─ {username: (salt, sha256(salt+pw))}
        │   ├─ attackers.attempt_rainbow_on_salted(sdb, rt)  → 0 cracked
        │   │
        │   ├─ preventions.hash_database_stretched(users, K)
        │   │       └─ {username: (salt, stretch(salt+pw, K), K)}
        │   ├─ preventions.attempt_rainbow_on_stretched(stdb, rt)  → 0 cracked
        │   │
        │   ├─ preventions.hash_database_peppered(users, pepper)
        │   │       └─ {username: (salt, sha256(pepper+salt+pw))}
        │   ├─ preventions.attempt_rainbow_on_peppered(pdb, rt)  → 0 cracked
        │   │
        │   ├─ metrics.calculate_success_rate(cracked, N)  × 4
        │   │
        │   └─ test_cb(u_sr, s_sr, st_sr, p_sr)
        │           └─ gui appends to _live_u, _live_d, redraws live graph
        │
        ├─ _summarise(results)
        └─ _log_final(log, summary)

gui._results = results
gui STATS labels updated
Progress bar → 100%
```

---

*This document was generated from the source code as of the v2 branch.*
