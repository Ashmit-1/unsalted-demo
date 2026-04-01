# Graph Explanations

---

## Graph 1 — Attack Success Rate: All Four Systems

**What it shows:**
For each test run, what percentage of user passwords did the attacker successfully crack using the rainbow table attack?

**X-axis:** Test case ID
**Y-axis:** Attack success rate (0–100%)

**How to explain:**
Unsalted hovers near 90–100% — almost every account cracked instantly. Salted, stretched, and peppered all sit flat at 0% because the rainbow table is completely useless against them. The dashed line at 90% is a threshold marker. The point of this graph is to show that simply adding a salt completely defeats a rainbow table attack. All three secure methods overlap on the same flat line at the bottom — they are indistinguishable from a success-rate perspective.

---

## Graph 2 — Time vs Dictionary Size / Work Formula Proof

**What it shows:**
Validates the theoretical formula `W = |D| × T_h` (work = dictionary size × time per hash).

**Left plot:** Actual precompute time (red dots) vs predicted time (green triangles) as dictionary size grows. A trend line shows the relationship is linear.

**Right plot:** Predicted W vs observed time — points should hug the `y = x` diagonal if the formula is accurate.

**How to explain:**
This graph proves our theoretical formula matches reality. As dictionary size doubles, precompute time doubles — it is O(|D|). The right scatter plot shows predicted vs actual time almost perfectly on the diagonal, confirming the formula `W = |D| × T_h` is mathematically valid and not just theoretical. This is the mathematical foundation the entire project rests on.

---

## Graph 3 — CIA Triad (Confidentiality / Integrity / Authentication)

**What it shows:**
Converts attack success rate into CIA security scores. Lower success rate = higher security score.

**Formulas used:**
- Confidentiality = `100 - success_rate`
- Integrity = `100 - success_rate × 0.85`
- Authentication = `100 - success_rate × 0.90`

**Left:** Grouped bar chart per CIA category, all four methods side by side.
**Right:** Radar (spider) chart — larger area covered = more secure.

**How to explain:**
CIA stands for Confidentiality, Integrity, and Authentication — the three pillars of information security. Unsalted scores near 0 on all three since it is almost fully cracked. Salted, stretched, and peppered score near 100 on all three. The radar chart makes the difference visually obvious — unsalted is a tiny collapsed triangle, while the secure methods fill the entire chart. This graph connects the technical attack results to real-world security principles.

---

## Graph 4 — Attack vs Prevention Latency Overhead

**What it shows:**
How long the attack itself takes (in seconds) across test runs, displayed on a log scale.

**Left:** Line plot per method over all test IDs.
**Right:** Box plot showing the distribution of attack times per method.

**How to explain:**
The Y-axis is a log scale because the difference in times spans many orders of magnitude. Unsalted attacks are nearly instant — the line sits flat near the bottom. Stretched attacks take significantly longer because the attacker must compute K=1000 hashes per guess instead of one. The box plot on the right shows the spread and median for each method. This graph shows the cost the attacker pays per attempt — stretching directly inflates that cost by the factor K.

---

## Graph 5 — Security Improvement Across Prevention Methods

**What it shows:**
How much better each secure method is compared to unsalted as the baseline, and a direct average success rate comparison.

**Left:** Bar chart of `unsalted_success_rate − method_success_rate` (improvement in percentage points) per test.
**Right:** Average success rate bar chart for all four methods.

**How to explain:**
The left chart quantifies the improvement over unsalted. Since salted, stretched, and peppered all crack 0%, their improvement equals whatever unsalted cracked — often 90%+. The right chart shows average success rates: unsalted near 90%, the other three near 0%. This graph makes the comparison stark with a single number: switching from unsalted to salted gives roughly a 90 percentage point security improvement at no meaningful performance cost to the legitimate user.

---

## Graph 6 — Work Complexity & Hash Clustering

**What it shows:**
Two separate things — theoretical work complexity at scale, and the hash clustering weakness of unsalted databases.

**Left:** Theoretical work W on a log scale vs dictionary size for unsalted, salted, and stretched.
- Unsalted:   `W = |D| × T_h`
- Salted:     `W = N × |D| × T_h`
- Stretched:  `W = N × |D| × K × T_h`

**Right:** Number of duplicate hash clusters vs number of users, coloured by reuse probability.

**How to explain:**
The left plot shows that as dictionary size grows, all three methods grow linearly — but at very different scales. Salted is N times higher than unsalted, and stretched is N×K times higher. This is why stretching matters at scale: the same hardware becomes exponentially less effective for the attacker. The right plot shows the unsalted weakness directly — more users combined with higher password reuse probability produces more hash clusters. If 15 users share the same hash, cracking one password instantly cracks all 15 accounts. Salting eliminates clusters entirely because every user gets a unique hash even if they share the same password.

---

## One-Line Summary

| Graph | What it proves |
|---|---|
| 1 | Rainbow table cracks unsalted; fails completely on salted, stretched, peppered |
| 2 | Precompute time scales linearly with dict size, confirming `W = |D| × T_h` |
| 3 | CIA scores — unsalted fails all three pillars, secure methods ace all three |
| 4 | Attack latency — stretched forces the attacker to spend K× more time per guess |
| 5 | Salting alone gives ~90 percentage point improvement over unsalted baseline |
| 6 | Work complexity at scale + hash clustering showing password reuse catastrophe |
