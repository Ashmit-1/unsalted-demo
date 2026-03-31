"""
Password Hash Attack & Prevention — GUI
Aesthetic: Bloomberg terminal × Dieter Rams.
4 colours: #000000 · #0d0d0d · #ffffff · #00ff41
"""

import threading
import csv
import random
import time
import sys

try:
    import customtkinter as ctk
except ImportError:
    print("Install customtkinter:  pip install customtkinter")
    sys.exit(1)

import tkinter as tk
from tkinter import filedialog, messagebox
import tkinter.ttk as ttk

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk

from comparison_runner import run_full_comparison
from metrics import calculate_success_rate
from sha256_manual import sha256 as _sha256
from hash_systems import generate_salt as _gen_salt
from preventions import get_server_pepper as _get_pepper

# ── Palette ───────────────────────────────────────────────────────────────────
BK   = "#000000"
PNL  = "#0d0d0d"
WH   = "#ffffff"
GRN  = "#00ff41"
DIM  = "#333333"
MID  = "#555555"
RED  = "#ef4444"
AMB  = "#f59e0b"
BLU  = "#60a5fa"
MONO = "Courier New"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


# ─────────────────────────────────────────────────────────────────────────────
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("")
        self.geometry("1280x820")
        self.minsize(1000, 680)
        self.configure(fg_color=BK)
        self.overrideredirect(True)

        self._drag_x = self._drag_y = 0
        self._blink  = True
        self._stop   = threading.Event()
        self._results = None
        self._is_fullscreen = False
        self._k_val  = 10          # current K (stretch iterations)
        self._live_u  = []         # live graph: unsalted SR per test
        self._live_d  = []         # live graph: defence avg SR per test
        self.bind("<Map>", self._on_map)

        self.attributes("-alpha", 0.0)
        self.after(10, lambda: self._fade(0.0))

        self._build()
        self._tick_cursor()

    # ── Fade-in ───────────────────────────────────────────────────────────────
    def _fade(self, a=0.0):
        a = min(a + 0.06, 1.0)
        self.attributes("-alpha", a)
        if a < 1.0:
            self.after(12, lambda: self._fade(a))

    # ── Drag ─────────────────────────────────────────────────────────────────
    def _press(self, e):
        self._drag_x, self._drag_y = e.x_root, e.y_root

    def _drag(self, e):
        self.geometry(f"+{self.winfo_x()+e.x_root-self._drag_x}"
                      f"+{self.winfo_y()+e.y_root-self._drag_y}")
        self._drag_x, self._drag_y = e.x_root, e.y_root

    def _minimize(self):
        self.overrideredirect(False)
        self.iconify()

    def _on_map(self, e):
        if str(e.widget) == str(self) and self.wm_state() == "normal":
            self.overrideredirect(True)

    def _toggle_fullscreen(self):
        if self._is_fullscreen:
            self.state("normal")
            if hasattr(self, "_normal_geom"):
                self.geometry(self._normal_geom)
            self._is_fullscreen = False
        else:
            self._normal_geom = self.geometry()
            self.state("zoomed")
            self._is_fullscreen = True

    # ── Blinking cursor ───────────────────────────────────────────────────────
    def _tick_cursor(self):
        if hasattr(self, "_cur"):
            self._cur.configure(text="█" if self._blink else " ")
            self._blink = not self._blink
        self.after(530, self._tick_cursor)

    # ══════════════════════════════════════════════════════════════════════════
    def _build(self):
        # ── Title bar ─────────────────────────────────────────────────────────
        bar = ctk.CTkFrame(self, fg_color=PNL, corner_radius=0, height=50)
        bar.pack(fill="x")
        bar.bind("<ButtonPress-1>", self._press)
        bar.bind("<B1-Motion>",     self._drag)

        title = ctk.CTkLabel(
            bar,
            text="  P A S S W O R D   H A S H   A T T A C K   &   P R E V E N T I O N",
            font=(MONO, 12, "bold"), text_color=WH, fg_color=PNL,
        )
        title.pack(side="left", padx=16, pady=14)
        for w in (bar, title):
            w.bind("<ButtonPress-1>", self._press)
            w.bind("<B1-Motion>",     self._drag)

        self._cur = ctk.CTkLabel(bar, text="█", font=(MONO, 15, "bold"),
                                 text_color=GRN, fg_color=PNL)
        self._cur.pack(side="left", padx=2)

        for sym, cmd in [("×", self.destroy), ("◻", self._toggle_fullscreen), ("−", self._minimize)]:
            ctk.CTkButton(
                bar, text=sym, width=38, height=38,
                fg_color=BK, border_width=1, border_color=DIM,
                hover_color=WH, text_color=WH,
                font=(MONO, 13, "bold"), corner_radius=0, command=cmd,
            ).pack(side="right", padx=2, pady=6)

        _line(self)

        # ── Body ──────────────────────────────────────────────────────────────
        body = tk.Frame(self, bg=BK)
        body.pack(fill="both", expand=True)

        left = tk.Frame(body, bg=PNL, width=240)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        self._sidebar(left)

        tk.Frame(body, bg=DIM, width=1).pack(side="left", fill="y")

        right = tk.Frame(body, bg=BK)
        right.pack(side="left", fill="both", expand=True)
        self._log_panel(right)

        # ── Status bar ────────────────────────────────────────────────────────
        _line(self)
        bot = tk.Frame(self, bg=PNL, height=34)
        bot.pack(fill="x")

        self._sdot = ctk.CTkLabel(bot, text="●", font=(MONO, 13),
                                  text_color=MID, fg_color=PNL)
        self._sdot.pack(side="left", padx=(14, 4))

        self._slbl = ctk.CTkLabel(bot, text="IDLE", font=(MONO, 9),
                                  text_color=MID, fg_color=PNL)
        self._slbl.pack(side="left")

        self._pv = ctk.DoubleVar(value=0)
        self._pb = ctk.CTkProgressBar(
            bot, variable=self._pv, width=200, height=5,
            fg_color=DIM, progress_color=WH, corner_radius=0,
        )
        self._pb.pack(side="right", padx=14, pady=14)

    # ── Sidebar ───────────────────────────────────────────────────────────────
    def _sidebar(self, p):
        def slbl(text, small=False):
            sz = 8 if small else 9
            ctk.CTkLabel(p, text=text, font=(MONO, sz), text_color=MID,
                         fg_color=PNL, anchor="w").pack(fill="x", padx=18, pady=(10, 2))

        # ── Settings ──────────────────────────────────────────────────────────
        slbl("S E T T I N G S")
        _line(p)

        self.vt = ctk.IntVar(value=25)
        self.vd = ctk.IntVar(value=2000)
        self.vr = ctk.DoubleVar(value=0.70)

        for label, var in [("num tests", self.vt), ("dict size", self.vd), ("reuse prob", self.vr)]:
            slbl(label, small=True)
            e = ctk.CTkEntry(p, textvariable=var, width=200, height=28,
                             fg_color=BK, border_color=DIM, border_width=1,
                             text_color=WH, font=(MONO, 10), corner_radius=0)
            e.pack(padx=18, pady=(0, 6))
            e.bind("<FocusIn>",  lambda ev, w=e: w.configure(border_color=GRN))
            e.bind("<FocusOut>", lambda ev, w=e: w.configure(border_color=DIM))

        # K slider (feature 6)
        slbl("stretch K", small=True)
        self._k_lbl = ctk.CTkLabel(p, text="K = 10  →  ×10 per guess",
                                    font=(MONO, 8), text_color=GRN, fg_color=PNL, anchor="w")
        self._k_lbl.pack(fill="x", padx=18, pady=(0, 3))

        def _on_k(v):
            k = max(1, int(round(float(v))))
            self._k_val = k
            self._k_lbl.configure(text=f"K = {k:,}  →  ×{k:,} per guess")

        k_slider = ctk.CTkSlider(p, from_=1, to=500, command=_on_k,
                                  width=200, height=16,
                                  button_color=GRN, button_hover_color=WH,
                                  progress_color=GRN, fg_color=DIM,
                                  corner_radius=0)
        k_slider.set(10)
        k_slider.pack(padx=18, pady=(0, 8))

        # ── Actions ───────────────────────────────────────────────────────────
        _line(p)
        slbl("A C T I O N S")

        self._btns = {}
        for label, cmd in [
            ("generate parameters", self._gen),
            ("run attack",          self._attack),
            ("apply prevention",    self._prevent),
            ("show graphs",         self._graphs),
            ("breach simulator",    self._breach_sim),
            ("live crack demo",     self._live_crack),
            ("export csv",          self._export),
            ("clear log",           self._clear),
        ]:
            b = ctk.CTkButton(
                p, text=label.upper(), command=cmd,
                width=200, height=30, corner_radius=0,
                fg_color=BK, border_width=1, border_color=WH,
                hover_color=WH, text_color=WH,
                font=(MONO, 8, "bold"),
            )
            b.pack(padx=18, pady=2)
            self._btns[label] = b

        # ── Stats ─────────────────────────────────────────────────────────────
        _line(p)
        slbl("S T A T S")

        self._sv = {}
        for k, col in [("unsalted", RED), ("salted", GRN),
                       ("stretched", GRN), ("peppered", GRN)]:
            frm = tk.Frame(p, bg=PNL)
            frm.pack(fill="x", padx=18, pady=2)
            tk.Label(frm, text=k, font=(MONO, 8), fg=MID, bg=PNL,
                     anchor="w").pack(side="left")
            lbl = tk.Label(frm, text="—", font=(MONO, 8, "bold"),
                           fg=col, bg=PNL, anchor="e")
            lbl.pack(side="right")
            self._sv[k] = lbl


    # ── Log panel ─────────────────────────────────────────────────────────────
    def _log_panel(self, p):
        hdr = tk.Frame(p, bg=BK, height=32)
        hdr.pack(fill="x")
        tk.Label(hdr, text="  O U T P U T   L O G",
                 font=(MONO, 9), fg=MID, bg=BK).pack(side="left", pady=8)
        _line(p)

        # Live graph frame at bottom — pack FIRST to reserve space
        tk.Frame(p, bg=DIM, height=1).pack(side="bottom", fill="x")
        self._lgf = tk.Frame(p, bg=BK, height=200)
        self._lgf.pack(side="bottom", fill="x")
        self._lgf.pack_propagate(False)

        # Scrollbar + text fill remaining space
        sb = tk.Scrollbar(p, orient="vertical", width=6,
                          troughcolor=BK, bg=DIM, activebackground=WH)
        self._txt = tk.Text(
            p, bg=BK, fg=WH, insertbackground=GRN,
            font=(MONO, 10), wrap="word",
            relief="flat", borderwidth=0, padx=20, pady=12,
            state="disabled",
        )
        sb.configure(command=self._txt.yview)
        self._txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._txt.pack(fill="both", expand=True)

        self._txt.tag_config("head", foreground="#a78bfa", font=(MONO, 10, "bold"))
        self._txt.tag_config("math", foreground=AMB)
        self._txt.tag_config("ok",   foreground=GRN)
        self._txt.tag_config("err",  foreground=RED)
        self._txt.tag_config("warn", foreground=AMB)
        self._txt.tag_config("info", foreground=BLU)
        self._txt.tag_config("dim",  foreground=MID)

        self._banner()
        self._init_live_graph()

    # ══════════════════════════════════════════════════════════════════════════
    # LOGGING HELPERS
    # ══════════════════════════════════════════════════════════════════════════
    def log(self, text: str, tag: str = ""):
        self._txt.configure(state="normal")
        self._txt.insert("end", text + "\n", tag if tag else ())
        self._txt.see("end")
        self._txt.configure(state="disabled")

    def _banner(self):
        self.log("  ╔══════════════════════════════════════════════════════╗", "head")
        self.log("  ║  PASSWORD HASH ATTACK & PREVENTION — FINAL REVIEW   ║", "head")
        self.log("  ║  Unsalted · Salted · Key-Stretched · Salt+Pepper    ║", "head")
        self.log("  ╚══════════════════════════════════════════════════════╝", "head")
        self.log("", "")
        self.log("  W O R K   C O M P L E X I T Y", "head")
        self.log("  Unsalted  :  W = |D| × T_h", "math")
        self.log("  Salted    :  W = N × |D| × T_h          (×N harder)", "math")
        self.log("  Stretched :  W = N × |D| × K × T_h      (×N·K harder)", "math")
        self.log("  Peppered  :  W = 2²⁵⁶ × N × |D| × T_h  (≈ impossible)", "math")
        self.log("", "")
        self.log("  ─── click  GENERATE PARAMETERS  to begin ───", "dim")

    def _setstatus(self, text, col=WH):
        self._slbl.configure(text=text, text_color=col)
        self._sdot.configure(text_color=col)

    def _setprog(self, pct):
        self._pv.set(pct)
        self._pb.configure(progress_color=GRN if pct >= 100 else WH)

    # ══════════════════════════════════════════════════════════════════════════
    # BUTTON HELPERS
    # ══════════════════════════════════════════════════════════════════════════
    def _set_busy(self, busy: bool):
        state = "disabled" if busy else "normal"
        for b in self._btns.values():
            b.configure(state=state)

    # ══════════════════════════════════════════════════════════════════════════
    # BUTTON HANDLERS
    # ══════════════════════════════════════════════════════════════════════════
    def _gen(self):
        self.log("", "")
        self.log("  G E N E R A T E   P A R A M E T E R S", "head")
        self.log("  " + "─" * 50, "dim")
        K = self._k_val
        self.log(f"  num tests        : {self.vt.get()}", "info")
        self.log(f"  dictionary size  : {self.vd.get():,} words", "info")
        self.log(f"  reuse probability: {self.vr.get():.0%}", "info")
        self.log(f"  stretch K        : {K:,} iterations", "info")
        self.log(f"  salt space       : 2¹²⁸ ≈ 3.4 × 10³⁸ salts", "info")
        self.log(f"  pepper space     : 2²⁵⁶ ≈ 1.2 × 10⁷⁷ keys", "info")
        self.log("", "")
        self.log("  M A T H   P R O O F", "head")
        self.log("  Unsalted  :  W = |D| × T_h", "math")
        self.log("  Salted    :  W = N × |D| × T_h              [×N]", "math")
        self.log(f"  Stretched :  W = N × |D| × {K:,} × T_h   [×N×{K:,}]", "math")
        self.log("  Peppered  :  W = 2²⁵⁶ × N × |D| × T_h     [×2²⁵⁶]", "math")
        self.log("", "")
        self.log("  ─── ready ───", "ok")
        self._setstatus("READY", WH)

    # ── Attack ────────────────────────────────────────────────────────────────
    def _attack(self):
        n = self.vt.get()
        d = self.vd.get()
        r = self.vr.get()
        self._set_busy(True)
        threading.Thread(target=self._attack_th, args=(n, d, r), daemon=True).start()

    def _attack_th(self, n, dict_size, reuse_prob):
        from database_generator import generate_dictionary, generate_users
        from hash_systems import hash_database
        from attackers import build_rainbow_table, crack_database

        try:
            self.after(0, lambda: self._setstatus("RUNNING ATTACK …", RED))
            self.after(0, lambda: self.log("", ""))
            self.after(0, lambda: self.log("  A T T A C K   P H A S E", "head"))
            self.after(0, lambda: self.log("  rainbow table precomputation on unsalted SHA-256", "dim"))
            self.after(0, lambda: self.log("  " + "─" * 50, "dim"))

            fd  = generate_dictionary(dict_size)
            srs = []

            for i in range(n):
                nu  = random.randint(50, 500)
                ds  = random.randint(len(fd) // 2, len(fd))
                dct = random.sample(fd, ds)
                u   = generate_users(nu, dct, reuse_prob)
                hdb, freq = hash_database(u)
                rt, pre_t = build_rainbow_table(dct)
                cr, lk    = crack_database(hdb, rt)
                T_h = pre_t / ds
                W_u = ds * T_h
                sr  = calculate_success_rate(len(cr), nu)
                srs.append(sr)
                # clustering insight
                dups = {h: c for h, c in freq.items() if c > 1}
                dup_note = ""
                if dups:
                    wh, wc = max(dups.items(), key=lambda x: x[1])
                    dup_note = f"  ⚑ {wc} share {wh[:8]}…"
                tag = "err" if sr >= 90 else "warn"
                msg = (f"  [{i+1:02d}]  N={nu:3d}  |D|={ds:4d}  "
                       f"W={W_u:.5f}s  cracked={len(cr)}/{nu}  SR={sr:.1f}%{dup_note}")
                self.after(0, lambda m=msg, t=tag: self.log(m, t))
                self.after(0, lambda p=(i+1)/n*100: self._setprog(p))

            avg  = sum(srs) / len(srs)
            ge90 = sum(1 for s in srs if s >= 90)
            self.after(0, lambda: self.log("", ""))
            self.after(0, lambda: self.log(f"  avg success : {avg:.1f}%   tests≥90%: {ge90}/{n}", "err"))
            self.after(0, lambda: self.log("  ⚠  VULNERABLE — precomputed table cracks all users", "err"))
            self.after(0, lambda: self._setstatus("● VULNERABLE", RED))
            self.after(0, lambda: self._sv["unsalted"].configure(text=f"{avg:.1f}%", fg=RED))
        finally:
            self.after(0, lambda: self._set_busy(False))

    # ── Prevention ────────────────────────────────────────────────────────────
    def _prevent(self):
        n = self.vt.get()
        d = self.vd.get()
        k = self._k_val
        self._stop.clear()
        self._set_busy(True)
        # reset live graph data
        self._live_u = []
        self._live_d = []
        threading.Thread(target=self._prevent_th, args=(n, d, k), daemon=True).start()

    def _prevent_th(self, n, dict_size, k_iter):
        try:
            self.after(0, lambda: self._setstatus("COMPARING …", AMB))

            def lcb(msg, tag):
                self.after(0, lambda m=msg, t=tag: self.log(m, t))

            def pcb(pct):
                self.after(0, lambda p=pct: self._setprog(p))

            def tcb(u_sr, s_sr, st_sr, p_sr):
                self.after(0, lambda u=u_sr, s=s_sr, st=st_sr, pp=p_sr:
                           self._update_live_graph(u, s, st, pp))

            res = run_full_comparison(
                num_tests=n,
                dict_base_size=dict_size,
                k_iter=k_iter,
                log_cb=lcb,
                progress_cb=pcb,
                stop_event=self._stop,
                test_cb=tcb,
            )
            self._results = res
            s = res["summary"]
            self.after(0, lambda: self._setstatus("● SECURE", GRN))
            self.after(0, lambda: self._sv["unsalted"].configure(text=f"{s['avg_unsalted_sr']:.1f}%",   fg=RED))
            self.after(0, lambda: self._sv["salted"].configure(text=f"{s['avg_salted_sr']:.1f}%",       fg=GRN))
            self.after(0, lambda: self._sv["stretched"].configure(text=f"{s['avg_stretched_sr']:.1f}%", fg=GRN))
            self.after(0, lambda: self._sv["peppered"].configure(text=f"{s['avg_peppered_sr']:.1f}%",   fg=GRN))
        finally:
            self.after(0, lambda: self._set_busy(False))

    # ── Graphs ────────────────────────────────────────────────────────────────
    def _graphs(self):
        if not self._results:
            messagebox.showinfo("no data", "run 'apply prevention' first")
            return

        win = ctk.CTkToplevel(self)
        win.title("graphs")
        win.geometry("1080x700")
        win.configure(fg_color=BK)
        win.after(100, win.focus_force)

        from graph_generator import generate_all_graphs
        figs = generate_all_graphs(self._results)

        style = ttk.Style(win)
        style.theme_use("clam")
        style.configure("TNotebook",     background=BK, borderwidth=0)
        style.configure("TNotebook.Tab", background=PNL, foreground=WH,
                        font=(MONO, 9), padding=[10, 4])
        style.map("TNotebook.Tab",
                  background=[("selected", DIM)],
                  foreground=[("selected", WH)])

        nb = ttk.Notebook(win)
        nb.pack(fill="both", expand=True, padx=4, pady=4)

        tabs = ["1 · success rate", "2 · work formula", "3 · CIA",
                "4 · latency", "5 · improvement", "6 · complexity"]

        for fig, tab in zip(figs, tabs):
            f = tk.Frame(nb, bg=BK)
            nb.add(f, text=tab)
            cv = FigureCanvasTkAgg(fig, master=f)
            cv.draw()
            tb = NavigationToolbar2Tk(cv, f)
            tb.configure(background=PNL)
            tb.update()
            cv.get_tk_widget().pack(fill="both", expand=True)

        self.log(f"  ✔  {len(figs)} graphs ready", "ok")

    # ── Export ────────────────────────────────────────────────────────────────
    def _export(self):
        if not self._results:
            messagebox.showinfo("no data", "run experiments first")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile="comparison_results.csv",
        )
        if not path:
            return
        u, s, st, p = (self._results[k] for k in ["unsalted", "salted", "stretched", "peppered"])
        rows = [{
            "test_id":        ur["test_id"],
            "num_users":      ur["num_users"],
            "dict_size":      ur["dict_size"],
            "unsalted_sr_%":  round(ur["success_rate"],  2),
            "salted_sr_%":    round(sr["success_rate"],  2),
            "stretched_sr_%": round(str_["success_rate"], 2),
            "peppered_sr_%":  round(pr["success_rate"],  2),
            "unsalted_time_s": round(ur["attack_time"],   6),
        } for ur, sr, str_, pr in zip(u, s, st, p)]
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys())
            w.writeheader()
            w.writerows(rows)
        self.log(f"  ✔  {len(rows)} rows → {path}", "ok")

    # ── Clear ─────────────────────────────────────────────────────────────────
    def _clear(self):
        self._txt.configure(state="normal")
        self._txt.delete("1.0", "end")
        self._txt.configure(state="disabled")
        self._banner()
        self._setstatus("IDLE", MID)
        self._setprog(0)
        self._live_u = []
        self._live_d = []
        self._reset_live_graph()

    # ══════════════════════════════════════════════════════════════════════════
    # FEATURE 1 — LIVE PASSWORD CRACKER
    # ══════════════════════════════════════════════════════════════════════════
    def _live_crack(self, event=None):
        # Open entry window first — professor types password here
        entry_win = tk.Toplevel()
        entry_win.title("LIVE CRACK DEMO")
        entry_win.configure(bg=BK)
        entry_win.geometry("540x160")
        entry_win.resizable(False, False)
        entry_win.attributes("-topmost", True)
        entry_win.after(150, lambda: entry_win.attributes("-topmost", False))
        entry_win.lift()
        entry_win.focus_force()

        ctk.CTkLabel(
            entry_win,
            text="  E N T E R   A   P A S S W O R D   T O   C R A C K",
            font=(MONO, 11, "bold"), text_color=WH, fg_color=PNL,
        ).pack(fill="x")
        tk.Frame(entry_win, bg=DIM, height=1).pack(fill="x")

        frm = tk.Frame(entry_win, bg=BK)
        frm.pack(fill="x", padx=24, pady=20)

        pw_var = ctk.StringVar()
        e = ctk.CTkEntry(
            frm, textvariable=pw_var, placeholder_text="type any password…",
            width=320, height=36, fg_color=PNL, border_color=RED,
            border_width=1, text_color=WH, font=(MONO, 12), corner_radius=0,
        )
        e.pack(side="left", padx=(0, 10))
        e.focus_set()

        def _run():
            pw = pw_var.get().strip()
            if not pw:
                return
            entry_win.destroy()
            self._run_crack_demo(pw)

        ctk.CTkButton(
            frm, text="A T T A C K", command=_run,
            width=120, height=36, corner_radius=0,
            fg_color=RED, hover_color=WH, text_color=WH,
            font=(MONO, 9, "bold"),
        ).pack(side="left")
        e.bind("<Return>", lambda _: _run())

    def _run_crack_demo(self, pw):
        from database_generator import generate_dictionary
        from attackers import build_rainbow_table
        from preventions import hash_password_stretched, hash_password_peppered, get_server_pepper

        # Build a real dictionary that includes the typed password
        base_dict = generate_dictionary(60)
        if pw not in base_dict:
            base_dict.append(pw)

        rt, build_t = build_rainbow_table(base_dict)

        # Real lookups
        h_u           = _sha256(pw)
        in_table      = h_u in rt          # True — we inserted pw into dict
        salt          = _gen_salt()
        h_s           = _sha256(salt + pw)
        salt_in_table = h_s in rt          # False — salt not in table

        # Stretched: salt + K iterations
        K = self._k_val
        salt_st, h_st, iters = hash_password_stretched(pw, iterations=K)
        st_in_table = h_st in rt           # False

        # Peppered: pepper + salt + pw
        pepper    = get_server_pepper()
        salt_p, h_p = hash_password_peppered(pw)
        p_in_table  = h_p in rt            # False

        # Pick 5 sample entries for the "scrolling table" reveal
        import random as _rng
        sample_pairs = _rng.sample(
            [(w, h) for h, w in rt.items() if w != pw], min(5, len(rt) - 1)
        )

        # ── Open demo popup ──────────────────────────────────────────────
        # Use tk.Toplevel (not CTkToplevel) so Windows treats it as an
        # independent top-level window; CTkToplevel under overrideredirect
        # parents can silently hide behind the main window.
        win = tk.Toplevel()
        win.title("LIVE ATTACK DEMO")
        win.configure(bg=BK)
        win.geometry("900x600")
        win.resizable(True, True)
        win.attributes("-topmost", True)
        win.after(150, lambda: win.attributes("-topmost", False))
        win.lift()
        win.focus_force()

        hdr = ctk.CTkLabel(
            win,
            text=f"  L I V E   A T T A C K   D E M O   —   password: \"{pw}\"",
            font=(MONO, 12, "bold"), text_color=WH, fg_color=PNL,
        )
        hdr.pack(fill="x")
        tk.Frame(win, bg=DIM, height=1).pack(fill="x")

        sb  = tk.Scrollbar(win, orient="vertical", width=6,
                           troughcolor=BK, bg=DIM, activebackground=WH)
        txt = tk.Text(
            win, bg=BK, fg=WH, font=(MONO, 10), relief="flat",
            borderwidth=0, padx=24, pady=16, state="disabled", wrap="word",
        )
        sb.configure(command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True)

        txt.tag_config("head",  foreground="#a78bfa", font=(MONO, 10, "bold"))
        txt.tag_config("dim",   foreground=MID)
        txt.tag_config("hash",  foreground=AMB)
        txt.tag_config("crack", foreground=RED, font=(MONO, 12, "bold"))
        txt.tag_config("safe",  foreground=GRN, font=(MONO, 12, "bold"))
        txt.tag_config("ok",    foreground=GRN)
        txt.tag_config("err",   foreground=RED)
        txt.tag_config("info",  foreground=BLU)
        txt.tag_config("tbl",   foreground="#555599")
        txt.tag_config("hit",   foreground=RED, font=(MONO, 10, "bold"))

        tk.Frame(win, bg=DIM, height=1).pack(fill="x")
        ctk.CTkButton(
            win, text="CLOSE", command=win.destroy,
            width=120, height=28, corner_radius=0,
            fg_color=BK, border_width=1, border_color=DIM,
            hover_color=WH, text_color=WH, font=(MONO, 8, "bold"),
        ).pack(pady=6)

        def w(text, tag=""):
            txt.configure(state="normal")
            txt.insert("end", text + "\n", tag if tag else ())
            txt.see("end")
            txt.configure(state="disabled")

        # Accumulating delay — each call schedules from the last
        ms = [0]

        def later(dt, text, tag=""):
            ms[0] += dt
            win.after(ms[0], lambda t=text, g=tag: w(t, g))

        # ── Phase 1: build table ──────────────────────────────────────────
        later(0,   "  ┌─ PHASE 1 · BUILD THE RAINBOW TABLE ────────────────────────────┐", "head")
        later(20,  f"  │  dictionary  : {len(base_dict):,} common passwords  (includes target)", "info")
        later(20,  f"  │  computing sha256 for every word…", "dim")
        later(320, f"  │  built in     : {build_t*1000:.1f} ms   ({len(rt):,} entries in memory)", "info")
        later(20,  f"  │  lookup cost  : O(1)  — hash → plaintext, instant retrieval", "dim")
        later(20,  "  └────────────────────────────────────────────────────────────────┘", "head")
        later(20,  "", "")

        # ── Phase 2: unsalted attack ──────────────────────────────────────
        later(180, "  ┌─ PHASE 2 · ATTACK — UNSALTED DATABASE ────────────────────────┐", "head")
        later(20,  f"  │  victim stored :  sha256(\"{pw}\")", "dim")
        later(20,  f"  │  stored hash   :  {h_u}", "hash")
        later(20,  "  │", "dim")
        later(20,  "  │  sample of pre-built table entries:", "dim")
        for word, h in sample_pairs:
            later(80, f"  │    {h}  →  \"{word}\"", "tbl")
        later(120, f"  │    …", "tbl")
        later(20,  "  │", "dim")
        later(20,  "  │  querying table with stored hash…", "dim")
        later(360, f"  │  table[ {h_u[:24]}… ]", "dim")
        later(20,  f"  │         ↓", "err")
        later(160, f"  │       \"{pw}\"", "hit")
        later(20,  "  │", "dim")
        later(20,  f"  │  ██  C R A C K E D  ██  →  \"{pw}\"  in < 1 ms  (one dict lookup)", "crack")
        later(20,  "  │  table built once · reused against every account in the database", "err")
        later(20,  "  └────────────────────────────────────────────────────────────────┘", "head")
        later(20,  "", "")

        # ── Phase 3: salted attack ────────────────────────────────────────
        later(180, "  ┌─ PHASE 3 · SAME ATTACK — SALTED DATABASE ─────────────────────┐", "head")
        later(20,  f"  │  unique salt   :  {salt[:32]}…", "dim")
        later(20,  f"  │  stored hash   :  sha256( salt ‖ \"{pw}\" )", "dim")
        later(20,  f"  │               =  {h_s}", "hash")
        later(20,  "  │", "dim")
        later(20,  "  │  querying same table with this hash…", "dim")
        later(400, f"  │  table[ {h_s[:24]}… ]", "dim")
        later(20,  f"  │         ↓", "ok")
        later(160, f"  │       KeyError — NOT IN TABLE", "ok")
        later(20,  "  │", "dim")
        later(20,  f"  │  ✔  S E C U R E  —  the table is useless", "safe")
        later(20,  f"  │  attacker must compute sha256(salt‖w) for every w — O(N·|D|)", "ok")
        later(20,  f"  │  and this salt is unique per user, so the work can't be shared", "ok")
        later(20,  "  └────────────────────────────────────────────────────────────────┘", "head")
        later(20,  "", "")

        # ── Phase 4: stretched attack ─────────────────────────────────────
        later(180, "  ┌─ PHASE 4 · SAME ATTACK — KEY-STRETCHED DATABASE ──────────────┐", "head")
        later(20,  f"  │  salt           :  {salt_st[:32]}…", "dim")
        later(20,  f"  │  iterations K   :  {iters:,}  (sha256 applied {iters:,}× per guess)", "info")
        later(20,  f"  │  stored hash    :  stretch( salt ‖ \"{pw}\", K={iters:,} )", "dim")
        later(20,  f"  │               =  {h_st}", "hash")
        later(20,  "  │", "dim")
        later(20,  "  │  querying same table with this hash…", "dim")
        later(400, f"  │  table[ {h_st[:24]}… ]", "dim")
        later(20,  f"  │         ↓", "ok")
        later(160, f"  │       KeyError — NOT IN TABLE", "ok")
        later(20,  "  │", "dim")
        later(20,  f"  │  ✔  S E C U R E  —  table still useless", "safe")
        later(20,  f"  │  brute-force cost now ×{iters:,} per guess  →  O(N·|D|·K)", "ok")
        later(20,  f"  │  even cracking one account takes {iters:,}× more compute", "ok")
        later(20,  "  └────────────────────────────────────────────────────────────────┘", "head")
        later(20,  "", "")

        # ── Phase 5: peppered attack ──────────────────────────────────────
        later(180, "  ┌─ PHASE 5 · SAME ATTACK — SALT + PEPPER DATABASE ──────────────┐", "head")
        later(20,  f"  │  server pepper  :  (secret — never stored in DB)", "info")
        later(20,  f"  │  salt           :  {salt_p[:32]}…", "dim")
        later(20,  f"  │  stored hash    :  sha256( pepper ‖ salt ‖ \"{pw}\" )", "dim")
        later(20,  f"  │               =  {h_p}", "hash")
        later(20,  "  │", "dim")
        later(20,  "  │  querying same table with this hash…", "dim")
        later(400, f"  │  table[ {h_p[:24]}… ]", "dim")
        later(20,  f"  │         ↓", "ok")
        later(160, f"  │       KeyError — NOT IN TABLE", "ok")
        later(20,  "  │", "dim")
        later(20,  f"  │  ✔  S E C U R E  —  even if the DB is stolen", "safe")
        later(20,  f"  │  pepper is server-side only (env var / HSM)", "ok")
        later(20,  f"  │  attacker must brute-force 2²⁵⁶ pepper space — computationally", "ok")
        later(20,  f"  │  infeasible: ≈ 1.2 × 10⁷⁷ keys to try before a single crack", "ok")
        later(20,  "  └────────────────────────────────────────────────────────────────┘", "head")
        later(20,  "", "")

        # ── Verdict ───────────────────────────────────────────────────────
        later(180, "  V E R D I C T", "head")
        later(20,  f"  unsalted   →  cracked in < 1 ms  (O(1) table lookup)             ⚠", "err")
        later(20,  f"  salted     →  table attack fails  (O(N·|D|) per user)             ✔", "ok")
        later(20,  f"  stretched  →  table fails + ×{iters:,} cost per guess                ✔", "ok")
        later(20,  f"  peppered   →  table fails + 2²⁵⁶ pepper space (≈ impossible)      ✔", "ok")
        later(20,  "", "")
        later(20,  f"  the table cost {build_t*1000:.1f} ms to build — but it cracks every unsalted", "dim")
        later(20,  f"  account instantly, forever, at zero marginal cost per account.", "dim")

    # ══════════════════════════════════════════════════════════════════════════
    # FEATURE 2 — BREACH SIMULATOR
    # ══════════════════════════════════════════════════════════════════════════
    def _breach_sim(self):
        from database_generator import generate_dictionary, generate_users
        from hash_systems import hash_database, hash_database_salted

        # Tiny DB designed for maximum visible clustering
        d     = generate_dictionary(10)
        users = generate_users(30, d, reuse_probability=0.95)
        hdb, freq = hash_database(users)
        sdb       = hash_database_salted(users)

        win = ctk.CTkToplevel(self)
        win.title("BREACH SIMULATOR")
        win.geometry("1060x560")
        win.configure(fg_color=BK)
        win.after(80, win.focus_force)

        # Header
        ctk.CTkLabel(
            win,
            text="  DATABASE BREACH — UNSALTED  vs  SALTED   (30 users · reuse 95 %)",
            font=(MONO, 11, "bold"), text_color=WH, fg_color=PNL,
        ).pack(fill="x")
        _line(win)

        body = tk.Frame(win, bg=BK)
        body.pack(fill="both", expand=True, padx=6, pady=6)

        # ── Left: UNSALTED ────────────────────────────────────────────────────
        lf = tk.Frame(body, bg=BK)
        lf.pack(side="left", fill="both", expand=True, padx=(0, 3))

        tk.Label(lf, text="  ⚠  UNSALTED DATABASE  —  VULNERABLE",
                 font=(MONO, 9, "bold"), fg=RED, bg=BK).pack(fill="x")
        tk.Frame(lf, bg=RED, height=1).pack(fill="x")

        l_txt = tk.Text(lf, bg=BK, fg=WH, font=("Courier New", 8),
                        state="normal", relief="flat", borderwidth=0, padx=8, pady=4)
        l_txt.tag_config("dup",    foreground=RED)
        l_txt.tag_config("uniq",   foreground=MID)
        l_txt.tag_config("hdr",    foreground=MID, font=("Courier New", 8, "bold"))

        l_txt.insert("end", f"  {'USER':11s}  {'HASH (first 28 chars)':28s}  VERDICT\n", "hdr")
        l_txt.insert("end", "  " + "─" * 60 + "\n", "hdr")

        for uname, h in sorted(hdb.items()):
            cnt = freq.get(h, 1)
            if cnt > 1:
                verdict = f"×{cnt} DUPLICATE — ONE CRACK = {cnt} ACCOUNTS"
                tag = "dup"
            else:
                verdict = "unique"
                tag = "uniq"
            l_txt.insert("end", f"  {uname:11s}  {h[:28]}  {verdict}\n", tag)

        l_txt.configure(state="disabled")
        lsb = tk.Scrollbar(lf, orient="vertical", command=l_txt.yview, width=5,
                           troughcolor=BK, bg=DIM)
        l_txt.configure(yscrollcommand=lsb.set)
        lsb.pack(side="right", fill="y")
        l_txt.pack(fill="both", expand=True)

        # Divider
        tk.Frame(body, bg=DIM, width=1).pack(side="left", fill="y")

        # ── Right: SALTED ─────────────────────────────────────────────────────
        rf = tk.Frame(body, bg=BK)
        rf.pack(side="left", fill="both", expand=True, padx=(3, 0))

        tk.Label(rf, text="  ✔  SALTED DATABASE  —  SECURE",
                 font=(MONO, 9, "bold"), fg=GRN, bg=BK).pack(fill="x")
        tk.Frame(rf, bg=GRN, height=1).pack(fill="x")

        r_txt = tk.Text(rf, bg=BK, fg=WH, font=("Courier New", 8),
                        state="normal", relief="flat", borderwidth=0, padx=8, pady=4)
        r_txt.tag_config("ok",  foreground=GRN)
        r_txt.tag_config("hdr", foreground=MID, font=("Courier New", 8, "bold"))

        r_txt.insert("end", f"  {'USER':11s}  {'SALT':14s}  {'HASH (first 20 chars)':20s}  STATUS\n", "hdr")
        r_txt.insert("end", "  " + "─" * 60 + "\n", "hdr")

        for uname, (salt, h) in sorted(sdb.items()):
            r_txt.insert("end",
                         f"  {uname:11s}  {salt[:12]}…  {h[:20]}…  UNIQUE ✔\n", "ok")

        r_txt.configure(state="disabled")
        rsb = tk.Scrollbar(rf, orient="vertical", command=r_txt.yview, width=5,
                           troughcolor=BK, bg=DIM)
        r_txt.configure(yscrollcommand=rsb.set)
        rsb.pack(side="right", fill="y")
        r_txt.pack(fill="both", expand=True)

        # Footer
        _line(win)
        n_dup = sum(1 for c in freq.values() if c > 1)
        ctk.CTkLabel(
            win,
            text=f"  Unsalted: {n_dup} shared hashes  |  Salted: 0 shared hashes"
                 f"  |  Same 30 users · same passwords · different result",
            font=(MONO, 8), text_color=MID, fg_color=PNL,
        ).pack(fill="x")

    # ══════════════════════════════════════════════════════════════════════════
    # FEATURE 7 — LIVE ANIMATED GRAPH
    # ══════════════════════════════════════════════════════════════════════════
    def _init_live_graph(self):
        plt.rcParams.update({"font.family": "monospace", "font.size": 8})
        fig, ax = plt.subplots(figsize=(10, 2.1), facecolor=BK)
        ax.set_facecolor("#0d0d0d")
        ax.set_xlim(0, 1)
        ax.set_ylim(-8, 115)
        ax.set_ylabel("SR %", color=WH, fontsize=7)
        ax.tick_params(colors=WH, labelsize=7)
        for spine in ax.spines.values():
            spine.set_color(DIM)
        ax.text(0.5, 0.5,
                "run  A P P L Y   P R E V E N T I O N  to see live results",
                ha="center", va="center", color=MID, fontsize=8,
                transform=ax.transAxes, fontfamily="monospace")
        ax.set_title("Live Success Rate  (animates per test)", color=WH,
                     fontsize=8, pad=3, loc="left")
        fig.tight_layout(pad=0.4)

        self._live_fig    = fig
        self._live_ax     = ax
        self._live_canvas = FigureCanvasTkAgg(fig, master=self._lgf)
        self._live_canvas.draw()
        self._live_canvas.get_tk_widget().pack(fill="both", expand=True)

    def _update_live_graph(self, u_sr, s_sr, st_sr, p_sr):
        self._live_u.append(u_sr)
        self._live_d.append((s_sr + st_sr + p_sr) / 3)

        ax = self._live_ax
        ax.clear()
        ax.set_facecolor("#0d0d0d")

        ids = list(range(1, len(self._live_u) + 1))
        ax.plot(ids, self._live_u, color=RED,  linewidth=1.6, marker="o",
                markersize=3, label="Unsalted", alpha=0.9)
        ax.plot(ids, self._live_d, color=GRN,  linewidth=1.6, marker="o",
                markersize=3, label="Defences avg", alpha=0.9)
        ax.fill_between(ids, self._live_u, self._live_d, alpha=0.07,
                        color=GRN)

        ax.set_xlim(0.5, max(10, len(ids)) + 0.5)
        ax.set_ylim(-8, 115)
        ax.set_ylabel("SR %", color=WH, fontsize=7)
        ax.tick_params(colors=WH, labelsize=7)
        for spine in ax.spines.values():
            spine.set_color(DIM)
        ax.grid(color="#1a1a1a", alpha=0.6, linewidth=0.5)
        ax.legend(loc="upper right", fontsize=7,
                  facecolor=BK, labelcolor=WH, edgecolor=DIM)
        ax.set_title(
            f"Live Success Rate — test {len(ids)} / running",
            color=WH, fontsize=8, pad=3, loc="left",
        )
        self._live_fig.tight_layout(pad=0.4)
        self._live_canvas.draw()

    def _reset_live_graph(self):
        ax = self._live_ax
        ax.clear()
        ax.set_facecolor("#0d0d0d")
        ax.set_xlim(0, 1)
        ax.set_ylim(-8, 115)
        ax.set_ylabel("SR %", color=WH, fontsize=7)
        ax.tick_params(colors=WH, labelsize=7)
        for spine in ax.spines.values():
            spine.set_color(DIM)
        ax.text(0.5, 0.5,
                "run  A P P L Y   P R E V E N T I O N  to see live results",
                ha="center", va="center", color=MID, fontsize=8,
                transform=ax.transAxes, fontfamily="monospace")
        ax.set_title("Live Success Rate  (animates per test)", color=WH,
                     fontsize=8, pad=3, loc="left")
        self._live_fig.tight_layout(pad=0.4)
        self._live_canvas.draw()


# ── Helpers ───────────────────────────────────────────────────────────────────
def _line(parent):
    tk.Frame(parent, bg=DIM, height=1).pack(fill="x")


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
