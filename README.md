# Password Hash Attack & Prevention

Interactive desktop tool that runs real attacks against real hashed databases and shows — with live numbers — why unsalted SHA-256 is broken and how salt, key-stretching, and pepper fix it.

---

## What it shows

| System | Attacker success rate | Why |
|---|---|---|
| Plain SHA-256 | ~80–100% | One table cracks every account instantly |
| + Salt | 0% | Unique salt per user makes the table useless |
| + Salt + Stretching | 0% | Table still useless, every guess costs K× more |
| + Salt + Pepper | 0% | Server-side 256-bit secret — 2²⁵⁶ harder to brute-force |

---

## Setup

Python 3.10+ required.

```bash
pip install customtkinter matplotlib
python gui.py
```

---

## GUI layout

```
┌──────────────────┬──────────────────────────────────┬───────────────┐
│  CONFIGURATION   │         SCROLLING LOG            │    STATS      │
│                  │                                  │               │
│  Num Users       │  Attack output, formulas,        │  unsalted  %  │
│  Dict Size       │  verdicts, per-test results      │  salted    %  │
│  Num Tests       │                                  │  stretched %  │
│  Reuse %  ────   │  ┌──────────────────────────┐    │  peppered  %  │
│  Stretch K ───   │  │  Live graph (per test)   │    │               │
│                  │  │  Unsalted  ── red        │    │               │
│  ACTIONS         │  │  Defences  ── green      │    │               │
│  ─────────────   │  └──────────────────────────┘    │               │
│  run attack      │                                  │               │
│  run full comp.  │                                  │               │
│  apply prev.     │                                  │               │
│  show graphs     │                                  │               │
│  breach sim.     │                                  │               │
│  live crack demo │                                  │               │
│  export csv      │                                  │               │
│  clear log       │                                  │               │
└──────────────────┴──────────────────────────────────┴───────────────┘
```

---

## Controls

| Control | Default | What it controls |
|---|---|---|
| Num Users | 100 | Accounts generated per test round |
| Dict Size | 2000 | Attacker's wordlist size |
| Num Tests | 25 | Rounds in a full comparison |
| Reuse % | 0.70 | Fraction of users picking from the top 20% of passwords. Higher = more clustering = worse unsalted result |
| Stretch K | 10 | SHA-256 iterations per password guess. Every +1K costs the attacker K× more compute, costs the defender ~1 ms more per login |

---

## Features

### Run Attack
Unsalted rainbow table attack only. Builds a table, cracks the DB, logs time and success rate. Good for a quick baseline.

### Run Full Comparison
Runs `num_tests` rounds. Each round randomises N (50–500 users), reuse rate (50–90%), and dict size, then attacks all four systems with the same rainbow table. The live graph and STATS panel update after every test. Hit **stop** to interrupt.

Sample log output per round:
```
  ╔═ TEST 07  N=213  |D|=1847  reuse=68% ════════════════
  ║  [UNSALTED]   W = 1847 × T_h = 0.018s   SR=79%  ⚠
  ║  [SALTED]     W = 213×1847×T_h = 3.9s  (×213)   SR=0%  ✔
  ║  [STRETCHED]  W = 213×1847×10×T_h = 39s  (×2130) SR=0%  ✔
  ║  [PEPPERED]   W ≈ 4.87e+72 years                  SR=0%  ✔
  ╚════════════════════════════════════════════════════════
```

### Apply Prevention
Prints the work formulas with your current values substituted in, salt/pepper space sizes, and a recommendation block. No computation runs.

### Show Graphs
Opens a matplotlib window. Requires a completed comparison.
- Bar chart: average success rates across all four systems
- Line chart: per-test unsalted SR (red) vs defence average (green), shaded gap between them

### Breach Simulator
Shows what a stolen database actually looks like — side by side.

**Left (unsalted):** Users with the same password share the exact same hash. Cracking one hash exposes every account that reused that password.

**Right (salted):** Every row has a unique salt and a unique hash, even for identical passwords. No clustering. Each account must be attacked separately.

### Live Crack Demo
Type any password into the entry popup, hit Enter. A 900×600 window animates five phases with real computed hashes:

1. **Build table** — real dictionary including your password, timed
2. **Unsalted attack** — your hash found in the table in < 1 ms, cracked
3. **Salted attack** — salted hash not in table, lookup fails
4. **Stretched attack** — stretched hash not in table, K× cost explained
5. **Peppered attack** — peppered hash not in table, 2²⁵⁶ keyspace explained

Ends with a four-line verdict comparing all systems.

### Export CSV
Saves one row per test round. Columns: `test_id`, `num_users`, `dict_size`, `unsalted_sr_%`, `salted_sr_%`, `stretched_sr_%`, `peppered_sr_%`, `unsalted_time_s`. Requires a completed comparison.

---

## The math

### Symbols

| Symbol | Meaning |
|---|---|
| `\|D\|` | Dictionary size — number of candidate passwords the attacker has |
| `N` | Number of user accounts in the target database |
| `T_h` | Time to compute one SHA-256 hash (measured as `build_time / \|D\|`) |
| `K` | Stretch iterations — how many times SHA-256 is applied per guess |
| `W` | Attacker work — total compute cost to crack passwords |
| `SR` | Success rate — percentage of accounts recovered |

### Work formulas

```
Unsalted   W = |D| × T_h
Salted     W = N × |D| × T_h
Stretched  W = N × |D| × K × T_h
Peppered   W = 2²⁵⁶ × N × |D| × T_h
```

**Unsalted:** The attacker hashes the dictionary once, then every user is cracked at O(1) per lookup. N does not appear — database size is irrelevant to attacker cost.

**Salted:** The rainbow table is worthless. Each user has a unique 128-bit salt, so the attacker must redo `|D|` hashes per user. N becomes a direct multiplier.

**Stretched:** Same as salted, but every single guess costs K hashes instead of one (SHA-256 is applied in a chain). Legitimate login: ~1 ms overhead at K=1000. Attacker: 1000× more work per user.

**Peppered:** A 256-bit secret stored only on the server (never in the DB) is prepended before hashing. Without it, the attacker cannot verify any guess. 2²⁵⁶ ≈ 10⁷⁷ keys to exhaust. Practically infeasible even with infinite compute. Note: if the server itself is compromised, the pepper is exposed and security falls back to the salted case.

**Success rate:**
```
SR = (cracked / N) × 100
```

---

## Files

| File | Role |
|---|---|
| `gui.py` | Desktop application |
| `main.py` | Prints launch instructions |
| `sha256_manual.py` | Pure-Python SHA-256 (no hashlib, intentionally slow for measurable timings) |
| `database_generator.py` | Fake user database generator |
| `hash_systems.py` | Unsalted and salted hashing |
| `preventions.py` | Key-stretching and pepper hashing |
| `attackers.py` | Rainbow table builder and attack functions |
| `comparison_runner.py` | Four-way experiment orchestrator |
| `metrics.py` | Success rate and work estimation |
| `export_results.py` | CSV export |

Full technical reference (every function, constant, and internals): [`DEVELOPER_DOCS.md`](DEVELOPER_DOCS.md)

---

## Production note

This project uses a hand-rolled SHA-256 for visibility into timing. Do not use plain SHA-256 for passwords in production. Use **Argon2id** (`argon2-cffi`), **bcrypt**, or **scrypt** — all are memory-hard, include built-in salting, and are designed to remain hard as hardware improves.
