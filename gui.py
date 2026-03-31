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
"""
Password Hash Attack & Prevention — Final Review GUI

Aesthetic: Bloomberg terminal × Dieter Rams.
4 colours: #000000 · #0d0d0d · #ffffff · #00ff41
Font: JetBrains Mono / Courier New fallback.
"""

import threading
import csv
import random
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
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk

from comparison_runner import run_full_comparison
from metrics import calculate_success_rate

# ── Palette (4 values only) ───────────────────────────────────────────────────
BK   = "#000000"    # main background
PNL  = "#0d0d0d"    # panel / card surface
WH   = "#ffffff"    # primary text, active borders
GRN  = "#00ff41"    # single accent
DIM  = "#333333"    # inactive borders
MID  = "#555555"    # dim text
RED  = "#ef4444"    # error (not in palette — UI necessity)
MONO = "Courier New"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


# ─────────────────────────────────────────────────────────────────────────────
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("")
        self.geometry("1200x780")
        self.minsize(960, 640)
        self.configure(fg_color=BK)
        self.overrideredirect(True)

        self._drag_x = self._drag_y = 0
        self._blink  = True
        self._stop   = threading.Event()
        self._results = None
        self._is_fullscreen = False
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

    # ── Blinking block cursor ─────────────────────────────────────────────────
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

        _line(self)  # 1-px divider

        # ── Body ──────────────────────────────────────────────────────────────
        body = tk.Frame(self, bg=BK)
        body.pack(fill="both", expand=True)

        # Left sidebar (fixed width)
        left = tk.Frame(body, bg=PNL, width=224)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        self._sidebar(left)

        # 1-px vertical rule
        tk.Frame(body, bg=DIM, width=1).pack(side="left", fill="y")

        # Log area
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

        slbl("S E T T I N G S")
        _line(p)

        self.vt = ctk.IntVar(value=25)
        self.vd = ctk.IntVar(value=2000)
        self.vk = ctk.IntVar(value=10)
        self.vr = ctk.DoubleVar(value=0.70)

        for label, var in [
            ("num tests",  self.vt),
            ("dict size",  self.vd),
            ("stretch K",  self.vk),
            ("reuse prob", self.vr),
        ]:
            slbl(label, small=True)
            e = ctk.CTkEntry(p, textvariable=var, width=184, height=30,
                             fg_color=BK, border_color=DIM, border_width=1,
                             text_color=WH, font=(MONO, 10), corner_radius=0)
            e.pack(padx=18, pady=(0, 8))
            e.bind("<FocusIn>",  lambda ev, w=e: w.configure(border_color=GRN))
            e.bind("<FocusOut>", lambda ev, w=e: w.configure(border_color=DIM))

        _line(p)
        slbl("A C T I O N S")

        self._btns = {}
        for label, cmd in [
            ("generate parameters", self._gen),
            ("run attack",          self._attack),
            ("apply prevention",    self._prevent),
            ("show graphs",         self._graphs),
            ("export csv",          self._export),
            ("clear log",           self._clear),
        ]:
            b = ctk.CTkButton(
                p, text=label.upper(), command=cmd,
                width=184, height=34, corner_radius=0,
                fg_color=BK, border_width=1, border_color=WH,
                hover_color=WH, text_color=WH,
                font=(MONO, 9, "bold"),
            )
            b.pack(padx=18, pady=3)
            self._btns[label] = b

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

        self._txt = tk.Text(
            p, bg=BK, fg=WH, insertbackground=GRN,
            font=(MONO, 10), wrap="word",
            relief="flat", borderwidth=0, padx=20, pady=12,
            state="disabled",
        )
        sb = tk.Scrollbar(p, orient="vertical", command=self._txt.yview,
                          width=6, troughcolor=BK, bg=DIM, activebackground=WH)
        self._txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._txt.pack(fill="both", expand=True)

        self._txt.tag_config("head", foreground="#a78bfa", font=(MONO, 10, "bold"))
        self._txt.tag_config("math", foreground="#fb923c")
        self._txt.tag_config("ok",   foreground=GRN)
        self._txt.tag_config("err",  foreground=RED)
        self._txt.tag_config("warn", foreground="#f59e0b")
        self._txt.tag_config("info", foreground="#7dd3fc")
        self._txt.tag_config("dim",  foreground=MID)

        self._banner()

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
        K = self.vk.get()
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

    # ── Attack (unsalted only, fast demo) ─────────────────────────────────────
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

            fd = generate_dictionary(dict_size)
            srs = []

            for i in range(n):
                nu  = random.randint(50, 500)
                ds  = random.randint(len(fd)//2, len(fd))
                dct = random.sample(fd, ds)
                u   = generate_users(nu, dct, reuse_prob)
                hdb, freq = hash_database(u)
                rt, pre_t = build_rainbow_table(dct)
                cr, lk    = crack_database(hdb, rt)
                T_h = pre_t / ds
                W_u = ds * T_h
                sr  = calculate_success_rate(len(cr), nu)
                srs.append(sr)
                tag = "err" if sr >= 90 else "warn"
                msg = (f"  [{i+1:02d}]  N={nu:3d}  |D|={ds:4d}  "
                       f"W=|{ds:,}|×{T_h:.7f}={W_u:.5f}s  "
                       f"cracked={len(cr)}/{nu}  SR={sr:.1f}%")
                self.after(0, lambda m=msg, t=tag: self.log(m, t))
                self.after(0, lambda p=(i+1)/n*100: self._setprog(p))

            avg = sum(srs)/len(srs)
            ge90 = sum(1 for s in srs if s >= 90)
            self.after(0, lambda: self.log("", ""))
            self.after(0, lambda: self.log(f"  avg success : {avg:.1f}%   tests≥90%: {ge90}/{n}", "err"))
            self.after(0, lambda: self.log("  ⚠  VULNERABLE — precomputed table cracks all users", "err"))
            self.after(0, lambda: self._setstatus("● VULNERABLE", RED))
            self.after(0, lambda: self._sv["unsalted"].configure(text=f"{avg:.1f}%", fg=RED))
        finally:
            self.after(0, lambda: self._set_busy(False))

    # ── Prevention (full 4-way) ───────────────────────────────────────────────
    def _prevent(self):
        n = self.vt.get()
        d = self.vd.get()
        k = self.vk.get()
        self._stop.clear()
        self._set_busy(True)
        threading.Thread(target=self._prevent_th, args=(n, d, k), daemon=True).start()

    def _prevent_th(self, n, dict_size, k_iter):
        try:
            self.after(0, lambda: self._setstatus("COMPARING …", "#f59e0b"))

            def lcb(msg, tag):
                self.after(0, lambda m=msg, t=tag: self.log(m, t))

            def pcb(pct):
                self.after(0, lambda p=pct: self._setprog(p))

            res = run_full_comparison(
                num_tests=n,
                dict_base_size=dict_size,
                k_iter=k_iter,
                log_cb=lcb,
                progress_cb=pcb,
                stop_event=self._stop,
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
        style.configure("TNotebook",      background=BK, borderwidth=0)
        style.configure("TNotebook.Tab",  background=PNL, foreground=WH,
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
        u, s, st, p = (self._results[k] for k in ["unsalted","salted","stretched","peppered"])
        rows = [{
            "test_id": ur["test_id"], "num_users": ur["num_users"],
            "dict_size": ur["dict_size"],
            "unsalted_sr_%":   round(ur["success_rate"],  2),
            "salted_sr_%":     round(sr["success_rate"],  2),
            "stretched_sr_%":  round(str_["success_rate"],2),
            "peppered_sr_%":   round(pr["success_rate"],  2),
            "unsalted_time_s": round(ur["attack_time"],   6),
        } for ur, sr, str_, pr in zip(u, s, st, p)]
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys())
            w.writeheader(); w.writerows(rows)
        self.log(f"  ✔  {len(rows)} rows → {path}", "ok")

    def _clear(self):
        self._txt.configure(state="normal")
        self._txt.delete("1.0", "end")
        self._txt.configure(state="disabled")
        self._banner()
        self._setstatus("IDLE", MID)
        self._setprog(0)


# ── Helpers ───────────────────────────────────────────────────────────────────
def _line(parent):
    """1-pixel separator line."""
    tk.Frame(parent, bg=DIM, height=1).pack(fill="x")


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()