"""
GUI for Password Hash Attack & Prevention Demonstration.

Layout
──────
┌─────────────────────────────────────────────────────────┐
│  TITLE BAR                                              │
├──────────────┬──────────────────────────────────────────┤
│  CONTROLS    │  LOG OUTPUT (scrolled text)              │
│              │                                          │
│  [Generate]  │                                          │
│  [Attack]    │                                          │
│  [Prevent]   │                                          │
│  [Graphs]    │                                          │
│  [Export]    │                                          │
│              │                                          │
├──────────────┴──────────────────────────────────────────┤
│  STATUS BAR  ●  VULNERABLE / ● SECURE / ● READY        │
└─────────────────────────────────────────────────────────┘
"""

import os
import sys

# Ensure Tcl/Tk library paths are available at runtime (helps virtualenvs
# and some PyInstaller/packaging scenarios where init.tcl isn't found).
def _ensure_tcl_tk():
    if os.name != "nt":
        return
    base = getattr(sys, "base_prefix", sys.prefix)
    candidates = [
        os.path.join(base, "tcl", "tcl8.6"),
        os.path.join(base, "tcl", "tk8.6"),
        os.path.join(base, "tcl"),
        os.path.join(sys.exec_prefix, "tcl", "tcl8.6"),
    ]
    for cand in candidates:
        if not cand or not os.path.isdir(cand):
            continue
        for root, dirs, files in os.walk(cand):
            if "init.tcl" in files:
                # Force-set TCL/TK to the discovered install paths so tkinter
                # doesn't try to use stale temporary extraction paths.
                os.environ["TCL_LIBRARY"] = root
                tk_root = root.replace("tcl8.6", "tk8.6")
                if os.path.isdir(tk_root):
                    os.environ["TK_LIBRARY"] = tk_root
                return
    # no debug output


_ensure_tcl_tk()

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import random
import csv
import io
import sys

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import matplotlib.pyplot as plt

from database_generator import generate_dictionary, generate_users
from unsalted_system import hash_database
from attacker_unsalted import build_rainbow_table, crack_database
from salted_system import hash_database_salted
from attacker_salted import attempt_rainbow_on_salted, estimate_salted_work
from comparison_runner import run_comparison
from graph_generator import generate_all_graphs
from metrics import calculate_success_rate, estimate_work_unsalted

# ── Palette ──────────────────────────────────────────────────────────────────
BG       = "#1e1e2e"
PANEL    = "#2a2a3e"
ACCENT   = "#7c3aed"
RED      = "#ef4444"
GREEN    = "#22c55e"
YELLOW   = "#f59e0b"
FG       = "#e2e8f0"
FG_DIM   = "#94a3b8"
MONO     = "Consolas" if sys.platform == "win32" else "Courier New"

FONT_H1  = ("Segoe UI", 16, "bold")
FONT_H2  = ("Segoe UI", 11, "bold")
FONT_BTN = ("Segoe UI", 10, "bold")
FONT_LOG = (MONO, 10)


# ─────────────────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Hash Attack & Prevention — Final Review")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.configure(bg=BG)

        # ── State ─────────────────────────────────────────────────────────
        self._status       = "ready"      # ready | running | vulnerable | secure
        self._results      = None         # comparison results dict
        self._stop_event   = threading.Event()
        self._graph_figs   = []

        # ── Parameter variables ───────────────────────────────────────────
        self.v_num_tests   = tk.IntVar(value=25)
        self.v_dict_size   = tk.IntVar(value=2000)
        self.v_num_users   = tk.IntVar(value=200)
        self.v_reuse       = tk.DoubleVar(value=0.70)

        self._build_ui()
        self._log_banner()

    # ══════════════════════════════════════════════════════════════════════
    # UI CONSTRUCTION
    # ══════════════════════════════════════════════════════════════════════

    def _build_ui(self):
        # ── Header ────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=ACCENT, height=54)
        hdr.pack(fill=tk.X, side=tk.TOP)
        tk.Label(
            hdr, text="🔐  Password Hash Attack & Prevention",
            font=FONT_H1, bg=ACCENT, fg="white", pady=10
        ).pack(side=tk.LEFT, padx=18)
        tk.Label(
            hdr, text="Final Review — Unsalted vs Salted SHA-256",
            font=("Segoe UI", 10), bg=ACCENT, fg="#ddd6fe", pady=10
        ).pack(side=tk.LEFT)

        # ── Main body ─────────────────────────────────────────────────────
        body = tk.Frame(self, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=10, pady=(6, 4))

        # Left panel
        left = tk.Frame(body, bg=PANEL, width=230)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))
        left.pack_propagate(False)
        self._build_left_panel(left)

        # Right panel (log)
        right = tk.Frame(body, bg=PANEL)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._build_log_panel(right)

        # ── Status bar ────────────────────────────────────────────────────
        self._status_bar = tk.Frame(self, bg=PANEL, height=36)
        self._status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=(0, 6))
        self._status_dot  = tk.Label(self._status_bar, text="●", font=("Segoe UI", 16),
                                     bg=PANEL, fg=FG_DIM)
        self._status_dot.pack(side=tk.LEFT, padx=(12, 6))
        self._status_label = tk.Label(self._status_bar, text="READY — Generate parameters to begin",
                                      font=("Segoe UI", 10), bg=PANEL, fg=FG_DIM)
        self._status_label.pack(side=tk.LEFT)
        self._prog_var = tk.DoubleVar()
        self._prog = ttk.Progressbar(self._status_bar, variable=self._prog_var,
                                     maximum=100, length=180)
        self._prog.pack(side=tk.RIGHT, padx=12)

    # ─────────────────────────────────────────────────────────────────────
    def _build_left_panel(self, parent):
        tk.Label(parent, text="⚙  Parameters", font=FONT_H2,
                 bg=PANEL, fg=FG, pady=8).pack(fill=tk.X, padx=10)

        ttk.Separator(parent, orient='horizontal').pack(fill=tk.X, padx=8)

        params = [
            ("Num Tests",    self.v_num_tests,  5,   50),
            ("Dict Size",    self.v_dict_size,  500, 5000),
            ("Users/Test",   self.v_num_users,  50,  500),
            ("Reuse Prob",   self.v_reuse,      0.3, 1.0),
        ]

        for label, var, lo, hi in params:
            frm = tk.Frame(parent, bg=PANEL)
            frm.pack(fill=tk.X, padx=12, pady=4)
            tk.Label(frm, text=label, font=("Segoe UI", 9), bg=PANEL, fg=FG_DIM,
                     width=10, anchor='w').pack(side=tk.LEFT)
            if isinstance(var, tk.IntVar):
                tk.Spinbox(frm, from_=lo, to=hi, textvariable=var,
                           width=6, font=("Segoe UI", 9)).pack(side=tk.RIGHT)
            else:
                tk.Spinbox(frm, from_=lo, to=hi, textvariable=var,
                           increment=0.05, format="%.2f",
                           width=6, font=("Segoe UI", 9)).pack(side=tk.RIGHT)

        ttk.Separator(parent, orient='horizontal').pack(fill=tk.X, padx=8, pady=8)
        tk.Label(parent, text="▶  Actions", font=FONT_H2,
                 bg=PANEL, fg=FG).pack(fill=tk.X, padx=10)

        actions = [
            ("🗂  Generate Parameters", self._btn_generate, "#334155"),
            ("💀  Run Attack",          self._btn_attack,   RED),
            ("🛡  Apply Prevention",    self._btn_prevent,  GREEN),
            ("📊  Show Graphs",         self._btn_graphs,   ACCENT),
            ("💾  Export CSV",          self._btn_export,   "#0369a1"),
            ("🗑  Clear Log",           self._btn_clear,    "#374151"),
        ]

        self._buttons = {}
        for label, cmd, colour in actions:
            btn = tk.Button(
                parent, text=label, command=cmd,
                bg=colour, fg="white", font=FONT_BTN,
                relief=tk.FLAT, pady=7, cursor="hand2",
                activebackground=colour, activeforeground="white",
            )
            btn.pack(fill=tk.X, padx=10, pady=3)
            self._buttons[label] = btn

        ttk.Separator(parent, orient='horizontal').pack(fill=tk.X, padx=8, pady=8)

        # Mini stats panel
        tk.Label(parent, text="📈  Last Run Stats", font=FONT_H2,
                 bg=PANEL, fg=FG).pack(fill=tk.X, padx=10)
        self._stat_labels = {}
        for key in ["Unsalted SR", "Salted SR", "Avg Time", "Tests ≥90%"]:
            frm = tk.Frame(parent, bg=PANEL)
            frm.pack(fill=tk.X, padx=12, pady=2)
            tk.Label(frm, text=key + ":", font=("Segoe UI", 8),
                     bg=PANEL, fg=FG_DIM, width=11, anchor='w').pack(side=tk.LEFT)
            lbl = tk.Label(frm, text="—", font=("Segoe UI", 8, "bold"),
                           bg=PANEL, fg=FG, anchor='e')
            lbl.pack(side=tk.RIGHT)
            self._stat_labels[key] = lbl

    # ─────────────────────────────────────────────────────────────────────
    def _build_log_panel(self, parent):
        tk.Label(parent, text="📋  Output Log", font=FONT_H2,
                 bg=PANEL, fg=FG, pady=6).pack(fill=tk.X, padx=10)

        self._log = scrolledtext.ScrolledText(
            parent, font=FONT_LOG, bg="#0f172a", fg=FG,
            insertbackground=FG, relief=tk.FLAT,
            wrap=tk.WORD, padx=8, pady=6,
        )
        self._log.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0, 6))

        # Colour tags
        self._log.tag_config("head",    foreground="#a78bfa", font=(MONO, 10, "bold"))
        self._log.tag_config("ok",      foreground=GREEN)
        self._log.tag_config("warn",    foreground=YELLOW)
        self._log.tag_config("err",     foreground=RED)
        self._log.tag_config("info",    foreground="#7dd3fc")
        self._log.tag_config("math",    foreground="#fb923c")
        self._log.tag_config("dim",     foreground=FG_DIM)
        self._log.tag_config("bold",    font=(MONO, 10, "bold"))
        self._log.configure(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════════════════
    # LOGGING HELPERS
    # ══════════════════════════════════════════════════════════════════════

    def log(self, text: str, tag: str = ""):
        self._log.configure(state=tk.NORMAL)
        if tag:
            self._log.insert(tk.END, text + "\n", tag)
        else:
            self._log.insert(tk.END, text + "\n")
        self._log.see(tk.END)
        self._log.configure(state=tk.DISABLED)

    def _log_banner(self):
        self.log("╔══════════════════════════════════════════════════════════╗", "head")
        self.log("║   PASSWORD HASH ATTACK & PREVENTION — FINAL REVIEW      ║", "head")
        self.log("║   Unsalted SHA-256 (Vulnerable)  vs  Salted SHA-256     ║", "head")
        self.log("╚══════════════════════════════════════════════════════════╝", "head")
        self.log("")
        self.log("This tool demonstrates:", "info")
        self.log("  • Rainbow-table precomputation attack on unsalted hashes", "info")
        self.log("  • Why salting completely defeats precomputation", "info")
        self.log("  • Mathematical work analysis: W = |D|·T_h  vs  N·|D|·T_h", "info")
        self.log("")
        self.log("→ Click 'Generate Parameters' to start.", "dim")

    def _set_status(self, mode: str):
        """mode: ready | running | vulnerable | secure"""
        colours = {
            "ready":      (FG_DIM,  "READY — Generate parameters to begin"),
            "running":    (YELLOW,  "RUNNING — Please wait …"),
            "vulnerable": (RED,     "● VULNERABLE — Unsalted system cracked!"),
            "secure":     (GREEN,   "● SECURE — Salted system withstood attack!"),
        }
        col, msg = colours.get(mode, colours["ready"])
        self._status_dot.configure(fg=col)
        self._status_label.configure(text=msg, fg=col)
        self._status = mode

    # ══════════════════════════════════════════════════════════════════════
    # BUTTON ACTIONS
    # ══════════════════════════════════════════════════════════════════════

    # ── Generate ──────────────────────────────────────────────────────────
    def _btn_generate(self):
        self.log("")
        self.log("══════════════════════════════════════════════════", "head")
        self.log(" GENERATE PARAMETERS", "head")
        self.log("══════════════════════════════════════════════════", "head")
        n  = self.v_num_tests.get()
        ds = self.v_dict_size.get()
        nu = self.v_num_users.get()
        rp = self.v_reuse.get()

        self.log(f"  Num Tests        : {n}", "info")
        self.log(f"  Dictionary Size  : {ds:,} words", "info")
        self.log(f"  Users per Test   : {nu} (randomised 50–500)", "info")
        self.log(f"  Reuse Probability: {rp:.0%}", "info")
        self.log(f"  Salt Length      : 128 bits (16 bytes / user)", "info")
        self.log(f"  Hash Algorithm   : SHA-256 (manual, 64-round)", "info")
        self.log("")
        self.log("  Salt space: 2¹²⁸ ≈ 3.4 × 10³⁸ possible salts", "math")
        self.log("  Unsalted work  W  = |D| × T_h", "math")
        self.log("  Salted   work  W' = N × |D| × T_h   (×N harder)", "math")
        self.log("")
        self.log("✔  Parameters set.  Click 'Run Attack' to execute.", "ok")
        self._set_status("ready")

    # ── Attack (unsalted) ─────────────────────────────────────────────────
    def _btn_attack(self):
        if self._status == "running":
            return
        self._stop_event.clear()
        t = threading.Thread(target=self._run_attack_thread, daemon=True)
        t.start()

    def _run_attack_thread(self):
        self.after(0, lambda: self._set_status("running"))
        self.after(0, lambda: self._prog_var.set(0))
        self.after(0, lambda: self.log(""))
        self.after(0, lambda: self.log("══════════════════════════════════════════════════", "head"))
        self.after(0, lambda: self.log(" ATTACK PHASE — Unsalted Rainbow Table", "head"))
        self.after(0, lambda: self.log("══════════════════════════════════════════════════", "head"))

        n_tests = self.v_num_tests.get()
        ds_base = self.v_dict_size.get()

        from database_generator import generate_dictionary, generate_users
        from unsalted_system import hash_database
        from attacker_unsalted import build_rainbow_table, crack_database

        full_dict = generate_dictionary(ds_base)
        all_sr    = []
        all_times = []

        for i in range(n_tests):
            if self._stop_event.is_set():
                break

            n_users  = random.randint(50, 500)
            rp       = round(random.uniform(0.5, self.v_reuse.get()), 2)
            ds       = random.randint(len(full_dict) // 2, len(full_dict))
            dct      = random.sample(full_dict, ds)
            users    = generate_users(n_users, dct, rp)

            hdb, freq     = hash_database(users)
            rt, pre_t     = build_rainbow_table(dct)
            cracked, lk_t = crack_database(hdb, rt)

            sr    = calculate_success_rate(len(cracked), n_users)
            total = pre_t + lk_t
            all_sr.append(sr)
            all_times.append(total)

            tag  = "ok" if sr >= 90 else "warn"
            msg  = (f"  Test {i+1:2d}: N={n_users:3d} |D|={ds:4d}  "
                    f"Cracked={len(cracked):3d}/{n_users:3d}  "
                    f"SR={sr:5.1f}%  t={total:.4f}s")
            self.after(0, lambda m=msg, tg=tag: self.log(m, tg))

            pct = ((i + 1) / n_tests) * 100
            self.after(0, lambda p=pct: self._prog_var.set(p))

        # Summary
        if all_sr:
            avg_sr   = sum(all_sr)  / len(all_sr)
            avg_t    = sum(all_times) / len(all_times)
            ge90     = sum(1 for r in all_sr if r >= 90)
            self.after(0, lambda: self.log(""))
            self.after(0, lambda: self.log(f"  Average Success Rate : {avg_sr:.1f}%", "err"))
            self.after(0, lambda: self.log(f"  Tests ≥ 90%          : {ge90}/{len(all_sr)}", "err"))
            self.after(0, lambda: self.log(f"  Average Attack Time  : {avg_t:.4f} s", "info"))
            self.after(0, lambda: self.log(""))
            self.after(0, lambda: self.log("  ⚠  VULNERABLE: Rainbow table attack succeeds!", "err"))
            self.after(0, lambda: self._set_status("vulnerable"))
            self.after(0, lambda: self._update_stats(avg_sr, None, avg_t, ge90, len(all_sr)))

        self.after(0, lambda: self._prog_var.set(100))

    # ── Prevention (salted) ───────────────────────────────────────────────
    def _btn_prevent(self):
        if self._status == "running":
            return
        self._stop_event.clear()
        t = threading.Thread(target=self._run_full_comparison_thread, daemon=True)
        t.start()

    def _run_full_comparison_thread(self):
        self.after(0, lambda: self._set_status("running"))
        self.after(0, lambda: self._prog_var.set(0))
        self.after(0, lambda: self.log(""))
        self.after(0, lambda: self.log("══════════════════════════════════════════════════", "head"))
        self.after(0, lambda: self.log(" PREVENTION PHASE — Salted SHA-256", "head"))
        self.after(0, lambda: self.log("══════════════════════════════════════════════════", "head"))
        self.after(0, lambda: self.log("  Running full comparison (unsalted vs salted)…", "info"))

        n_tests = self.v_num_tests.get()
        ds_base = self.v_dict_size.get()

        def cb(tid, nu, ds, u_sr, s_sr, u_t):
            u_tag = "err" if u_sr >= 90 else "warn"
            s_tag = "ok"
            msg = (f"  [{tid:2d}] N={nu:3d} |D|={ds:4d}  "
                   f"Unsalted={u_sr:5.1f}%  Salted={s_sr:4.1f}%  "
                   f"t={u_t:.4f}s")
            self.after(0, lambda m=msg, ut=u_tag: self.log(m, ut))
            pct = (tid / n_tests) * 100
            self.after(0, lambda p=pct: self._prog_var.set(p))

        results = run_comparison(
            num_tests=n_tests,
            dict_base_size=ds_base,
            callback=cb,
            stop_event=self._stop_event,
        )
        self._results = results
        s = results["summary"]

        self.after(0, lambda: self.log(""))
        self.after(0, lambda: self.log("  ── SUMMARY ──", "head"))
        self.after(0, lambda: self.log(f"  Unsalted avg success  : {s['avg_unsalted_rate']:.1f}%", "err"))
        self.after(0, lambda: self.log(f"  Salted   avg success  : {s['avg_salted_rate']:.1f}%", "ok"))
        self.after(0, lambda: self.log(f"  Tests ≥90% (unsalted) : {s['tests_ge90_unsalted']}/{n_tests}", "info"))
        self.after(0, lambda: self.log(f"  Avg security improve  : {s['avg_security_improvement']:.1f} pp", "ok"))
        self.after(0, lambda: self.log(""))
        self.after(0, lambda: self._log_math_section(results))
        self.after(0, lambda: self.log(""))
        self.after(0, lambda: self.log("  ✔  SECURE: Salting defeats the rainbow table!", "ok"))
        self.after(0, lambda: self._set_status("secure"))
        self.after(0, lambda: self._update_stats(
            s["avg_unsalted_rate"], s["avg_salted_rate"],
            s["avg_unsalted_time"], s["tests_ge90_unsalted"], n_tests
        ))
        self.after(0, lambda: self._prog_var.set(100))

    def _log_math_section(self, results):
        self.log("  ── MATHEMATICAL VALIDATION ──", "head")
        u = results["unsalted"]
        for r in u[:5]:
            ds  = r["dict_size"]
            ht  = r["hash_time"]
            pred = r["predicted_W"]
            act  = r["precompute_time"]
            self.log(f"  Test {r['test_id']}: |D|={ds}  T_h={ht:.6f}s", "math")
            self.log(f"    Predicted W = |D|×T_h = {pred:.5f}s  |  Actual = {act:.5f}s", "math")
        self.log("")
        self.log("  Salted work multiplier (sample):", "math")
        for r in results["salted"][:3]:
            n   = r["num_users"]
            ds  = r["dict_size"]
            sw  = r["salted_W_estimate"]
            self.log(f"    N={n} |D|={ds}  W'=N×|D|×T_h ≈ {sw:.4f}s  (×{n} vs unsalted)", "math")

    # ── Graphs ────────────────────────────────────────────────────────────
    def _btn_graphs(self):
        if self._results is None:
            messagebox.showinfo("No Data", "Run 'Apply Prevention' first to generate results.")
            return
        self._open_graph_window()

    def _open_graph_window(self):
        win = tk.Toplevel(self)
        win.title("📊  Graphs & Comparative Analysis")
        win.geometry("1050x700")
        win.configure(bg=BG)

        self.log("Generating graphs…", "info")
        figs = generate_all_graphs(self._results)
        self._graph_figs = figs

        titles = [
            "1 · Before vs After Success Rate",
            "2 · Time vs Dictionary Size",
            "3 · CIA Security Properties",
            "4 · Attack vs Prevention Latency",
            "5 · Security Improvement %",
            "6 · Hash Clustering & Reuse",
        ]

        # Tabs
        nb = ttk.Notebook(win)
        nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        for fig, title in zip(figs, titles):
            frame = ttk.Frame(nb)
            nb.add(frame, text=title)

            canvas = FigureCanvasTkAgg(fig, master=frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            toolbar = NavigationToolbar2Tk(canvas, frame)
            toolbar.update()

        self.log(f"✔  {len(figs)} graphs generated.", "ok")

    # ── Export CSV ────────────────────────────────────────────────────────
    def _btn_export(self):
        if self._results is None:
            messagebox.showinfo("No Data", "Run experiments first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All", "*.*")],
            initialfile="results_comparison.csv",
        )
        if not path:
            return

        u = self._results["unsalted"]
        s = self._results["salted"]
        rows = []
        for ur, sr in zip(u, s):
            rows.append({
                "test_id":          ur["test_id"],
                "num_users":        ur["num_users"],
                "dict_size":        ur["dict_size"],
                "reuse_prob":       ur["reuse_prob"],
                "unsalted_cracked": ur["cracked"],
                "unsalted_sr_%":    round(ur["success_rate"], 2),
                "unsalted_time_s":  round(ur["attack_time"], 6),
                "salted_cracked":   sr["cracked"],
                "salted_sr_%":      round(sr["success_rate"], 2),
                "salted_time_s":    round(sr["attack_time"], 6),
                "security_improve": round(ur["success_rate"] - sr["success_rate"], 2),
            })

        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

        self.log(f"✔  Exported {len(rows)} rows → {path}", "ok")
        messagebox.showinfo("Exported", f"Results saved to:\n{path}")

    # ── Clear ─────────────────────────────────────────────────────────────
    def _btn_clear(self):
        self._log.configure(state=tk.NORMAL)
        self._log.delete("1.0", tk.END)
        self._log.configure(state=tk.DISABLED)
        self._log_banner()
        self._set_status("ready")

    # ── Stats panel helper ─────────────────────────────────────────────────
    def _update_stats(self, u_sr, s_sr, avg_t, ge90, total):
        self._stat_labels["Unsalted SR"].configure(
            text=f"{u_sr:.1f}%", fg=RED if u_sr >= 90 else YELLOW
        )
        if s_sr is not None:
            self._stat_labels["Salted SR"].configure(
                text=f"{s_sr:.1f}%", fg=GREEN
            )
        self._stat_labels["Avg Time"].configure(
            text=f"{avg_t:.4f}s", fg=FG
        )
        self._stat_labels["Tests ≥90%"].configure(
            text=f"{ge90}/{total}", fg=RED if ge90 > total * 0.5 else GREEN
        )


# ─────────────────────────────────────────────────────────────────────────────
def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
