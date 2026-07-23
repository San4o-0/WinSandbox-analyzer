import json
import math
import os
import queue
import shutil
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, ttk

import app_settings
import config
import i18n
import reputation
import sandbox_manager
import static_analysis
import verdict

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD

    DND_AVAILABLE = True
except ImportError:
    DND_AVAILABLE = False


THEMES = {
    "dark": {
        "bg": "#0f1115",
        "surface": "#171a21",
        "surface_hover": "#1d222c",
        "chip": "#222732",
        "border": "#2a2f3a",
        "accent": "#4f8cff",
        "accent_dark": "#3d74e0",
        "text": "#e8ebf1",
        "muted": "#8b93a3",
        "report_fg": "#c9d1de",
        "scroll_active": "#3a4150",
    },
    "light": {
        "bg": "#f2f4f8",
        "surface": "#ffffff",
        "surface_hover": "#f6f8fc",
        "chip": "#eef1f6",
        "border": "#d9dee7",
        "accent": "#3b76e8",
        "accent_dark": "#2f61c4",
        "text": "#1a1f29",
        "muted": "#697182",
        "report_fg": "#3a4250",
        "scroll_active": "#c3cad6",
    },
}

LEVEL_COLORS = {
    "clean": "#22c55e",
    "suspicious": "#f59e0b",
    "dangerous": "#ef4444",
}

SEVERITY_COLORS = {
    "danger": "#ef4444",
    "warn": "#f59e0b",
    "trust": "#22c55e",
    "info": "#4f8cff",
}

SEVERITY_ICONS = {"danger": "⛔", "warn": "⚠", "trust": "✓", "info": "ⓘ"}

ORIGIN_KEYS = ("ind_vt_", "ind_signed", "ind_sig_broken", "ind_unsigned")

ALL_STEPS = (
    ("status_static", "step_inspect", False),
    ("status_reputation", "step_reputation", True),
    ("sandbox_start", "step_sandbox", False),
    ("sandbox_analyzing", "step_watch", False),
)

UI_FONT = "Segoe UI"
MONO_FONT = "Consolas"


class SandCheckApp:
    def __init__(self, root):
        self.root = root
        self.settings = app_settings.load()
        self.msg_queue = queue.Queue()
        self.busy = False
        self.current_verdict = None
        self.current_static = None
        self.notice = ""
        self.status_key = "ready"
        self.settings_win = None
        self.progress_pos = 0.0
        self.progress_job = None
        self.stage = "idle"
        self.step_index = 0
        self.checked_name = ""
        self.spinner_angle = 0
        self.spinner_job = None
        self.score_shown = 0
        self.wrap_labels = []
        self.reveal_queue = []
        self.reveal_job = None
        self.idle_phase = 0.0
        self.idle_job = None
        self.logo_scan = 0.0
        self.logo_job = None
        self.root.geometry("1040x740")
        self.root.minsize(900, 620)
        self._build_ui()
        self.root.after(100, self._poll_queue)

    @property
    def C(self):
        return THEMES[self.settings["theme"]]

    def t(self, key, **params):
        return i18n.t(self.settings["language"], key, **params)

    def _build_ui(self):
        C = self.C
        self.root.title(self.t("app_title"))
        self.root.configure(bg=C["bg"])
        self.wrap_labels = []

        self._build_header()

        body = tk.Frame(self.root, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=24, pady=(4, 20))
        body.columnconfigure(0, minsize=300)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        left = tk.Frame(body, bg=C["bg"])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 16))
        right = tk.Frame(body, bg=C["bg"])
        right.grid(row=0, column=1, sticky="nsew")

        self._build_left(left)
        self._build_right(right)

        self._render_zone()
        self._draw_verdict()
        self._render_findings()

    def _build_header(self):
        C = self.C
        header = tk.Frame(self.root, bg=C["bg"])
        header.pack(fill="x", padx=24, pady=(18, 10))
        self.logo = tk.Canvas(header, width=34, height=36, bg=C["bg"],
                              highlightthickness=0)
        self.logo.pack(side="left", padx=(0, 10))
        self.logo_scan = 0.0
        self._draw_logo()
        self._animate_logo()
        tk.Label(header, text="Sand", bg=C["bg"], fg=C["text"],
                 font=(UI_FONT, 17, "bold")).pack(side="left")
        tk.Label(header, text="Check", bg=C["bg"], fg=C["accent"],
                 font=(UI_FONT, 17, "bold")).pack(side="left")
        tk.Label(header, text=self.t("subtitle"), bg=C["bg"], fg=C["muted"],
                 font=(UI_FONT, 9)).pack(side="left", padx=(12, 0), pady=(6, 0))
        gear = tk.Label(header, text="⚙", bg=C["bg"], fg=C["muted"],
                        font=(UI_FONT, 14), cursor="hand2")
        gear.pack(side="right")
        gear.bind("<Button-1>", lambda e: self._open_settings())
        gear.bind("<Enter>", lambda e: gear.config(fg=C["text"]))
        gear.bind("<Leave>", lambda e: gear.config(fg=C["muted"]))

    def _build_left(self, parent):
        C = self.C
        self.drop_zone = tk.Frame(parent, bg=C["surface"], bd=0, highlightthickness=1,
                                  highlightbackground=C["border"], highlightcolor=C["border"])
        self.drop_zone.pack(fill="x")

        self.progress = tk.Canvas(parent, height=3, bg=C["surface"], highlightthickness=0)
        self.progress.pack(fill="x", pady=(6, 0))
        if not self.busy:
            self.progress.pack_forget()

        self.choose_btn = tk.Button(
            parent, text=self.t("choose_file"), command=self._choose_file,
            bg=C["surface"] if self.busy else C["accent"],
            fg=C["muted"] if self.busy else "#ffffff",
            activebackground=C["accent_dark"], activeforeground="#ffffff",
            disabledforeground=C["muted"], state="disabled" if self.busy else "normal",
            relief="flat", bd=0, highlightthickness=0,
            cursor="watch" if self.busy else "hand2",
            font=(UI_FONT, 10, "bold"), pady=9,
        )
        self.choose_btn.pack(fill="x", pady=(12, 0))
        self.choose_btn.bind("<Enter>", self._btn_hover_on)
        self.choose_btn.bind("<Leave>", self._btn_hover_off)
        bg, fg = self._status_colors()
        self.status = tk.Label(parent, text=self.t(self.status_key), bg=bg, fg=fg,
                               font=(UI_FONT, 9, "bold"), justify="center",
                               wraplength=250, padx=14, pady=5)
        self.status.pack(pady=(10, 0))

        self.file_card = tk.Frame(parent, bg=C["bg"])
        self.file_card.pack(fill="x", pady=(14, 0))
        self.advice_card = tk.Frame(parent, bg=C["bg"])
        self.advice_card.pack(fill="both", expand=True, pady=(12, 0))

    def _build_right(self, parent):
        C = self.C
        self.verdict_card = tk.Frame(parent, bg=C["surface"], bd=0, highlightthickness=1,
                                     highlightbackground=C["border"], highlightcolor=C["border"])
        self.verdict_card.pack(fill="x")
        self.verdict_canvas = tk.Canvas(self.verdict_card, height=104, bg=C["surface"],
                                        highlightthickness=0)
        self.verdict_canvas.pack(fill="x")
        self.verdict_canvas.bind("<Configure>", self._draw_verdict)

        self.findings_title = tk.Label(parent, text=self.t("section_results"), bg=C["bg"],
                                       fg=C["text"], font=(UI_FONT, 12, "bold"), anchor="w")
        self.findings_title.pack(fill="x", pady=(16, 8))

        holder = tk.Frame(parent, bg=C["bg"])
        holder.pack(fill="both", expand=True)
        self.scroll_canvas = tk.Canvas(holder, bg=C["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(holder, command=self.scroll_canvas.yview,
                                  style="App.Vertical.TScrollbar")
        _style_scrollbar(holder, C)
        self.scroll_canvas.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.scroll_canvas.pack(side="left", fill="both", expand=True)
        self.findings = tk.Frame(self.scroll_canvas, bg=C["bg"])
        self.findings_window = self.scroll_canvas.create_window(
            (0, 0), window=self.findings, anchor="nw"
        )
        self.findings.bind(
            "<Configure>",
            lambda e: self.scroll_canvas.config(scrollregion=self.scroll_canvas.bbox("all")),
        )
        self.scroll_canvas.bind("<Configure>", self._on_scroll_resize)
        for widget in (self.scroll_canvas, self.findings):
            widget.bind("<MouseWheel>", self._on_wheel)
            widget.bind("<Button-4>", self._on_wheel)
            widget.bind("<Button-5>", self._on_wheel)

    def _on_scroll_resize(self, event):
        self.scroll_canvas.itemconfig(self.findings_window, width=event.width)
        for label, pad in self.wrap_labels:
            label.config(wraplength=max(event.width - pad, 120))

    def _on_wheel(self, event):
        delta = 1 if getattr(event, "num", 0) == 5 else -1 if getattr(event, "num", 0) == 4 else 0
        if delta == 0:
            delta = -1 if event.delta > 0 else 1
        self.scroll_canvas.yview_scroll(delta, "units")

    def _render_zone(self):
        C = self.C
        zone = self.drop_zone
        for attr in ("spinner_job", "idle_job"):
            job = getattr(self, attr)
            if job is not None:
                self.root.after_cancel(job)
                setattr(self, attr, None)
        for widget in zone.winfo_children():
            widget.destroy()
        zone.config(bg=C["surface"], highlightbackground=C["border"])
        if self.stage == "checking":
            self._build_zone_checking()
        elif self.stage == "done":
            self._build_zone_done()
        else:
            self._build_zone_idle()

    def _build_zone_idle(self):
        C = self.C
        zone = self.drop_zone
        self.idle_badge = tk.Canvas(zone, width=56, height=64, bg=C["surface"],
                                    highlightthickness=0)
        self.idle_badge.pack(pady=(30, 10))
        badge = self.idle_badge
        self._draw_idle_badge(0.0)
        self._animate_idle()
        hint = tk.Label(zone, text=self.t("drop_hint"), bg=C["surface"], fg=C["text"],
                        font=(UI_FONT, 11, "bold"), wraplength=250)
        hint.pack()
        sub = tk.Label(zone, text=self.t("drop_sub"), bg=C["surface"], fg=C["muted"],
                       font=(UI_FONT, 9))
        sub.pack(pady=(4, 12))

        types = tk.Label(zone, text=self.t("drop_types"), bg=C["surface"], fg=C["accent"],
                         font=(UI_FONT, 8), wraplength=250)
        types.pack()
        limit = tk.Label(zone, text=self.t("drop_limit", size=config.MAX_FILE_SIZE_MB),
                         bg=C["surface"], fg=C["muted"], font=(UI_FONT, 8))
        limit.pack(pady=(2, 26))

        widgets = (zone, badge, hint, sub, types, limit)
        for widget in widgets:
            widget.bind("<Enter>", self._zone_hover_on)
            widget.bind("<Leave>", self._zone_hover_off)
        if DND_AVAILABLE:
            for widget in widgets:
                widget.drop_target_register(DND_FILES)
                widget.dnd_bind("<<Drop>>", self._on_drop)

    def _build_zone_checking(self):
        C = self.C
        zone = self.drop_zone
        self.spinner = tk.Canvas(zone, width=34, height=34, bg=C["surface"],
                                 highlightthickness=0)
        self.spinner.pack(pady=(26, 10))
        name = self.checked_name or self.t("check_in_progress")
        tk.Label(zone, text=_ellipsis(name, 30), bg=C["surface"], fg=C["text"],
                 font=(UI_FONT, 10, "bold")).pack()
        steps = tk.Frame(zone, bg=C["surface"])
        steps.pack(pady=(12, 26), padx=20, anchor="w")
        for index, key in enumerate(label for _, label, _ in self._steps()):
            done = index < self.step_index
            active = index == self.step_index
            row = tk.Frame(steps, bg=C["surface"])
            row.pack(anchor="w", pady=3)
            mark = "✓" if done else ("●" if active else "○")
            color = LEVEL_COLORS["clean"] if done else (C["accent"] if active else C["muted"])
            tk.Label(row, text=mark, bg=C["surface"], fg=color,
                     font=(UI_FONT, 9, "bold"), width=2).pack(side="left")
            tk.Label(row, text=self.t(key), bg=C["surface"],
                     fg=C["text"] if active else C["muted"],
                     font=(UI_FONT, 9, "bold" if active else "normal")).pack(side="left")
        self._animate_spinner()

    def _build_zone_done(self):
        C = self.C
        zone = self.drop_zone
        badge = tk.Canvas(zone, width=44, height=44, bg=C["surface"], highlightthickness=0)
        badge.create_oval(2, 2, 42, 42, outline=LEVEL_COLORS["clean"], width=2)
        badge.create_line(14, 23, 20, 29, fill=LEVEL_COLORS["clean"], width=3, capstyle="round")
        badge.create_line(20, 29, 31, 16, fill=LEVEL_COLORS["clean"], width=3, capstyle="round")
        badge.pack(pady=(28, 10))
        tk.Label(zone, text=self.t("done_title"), bg=C["surface"], fg=C["text"],
                 font=(UI_FONT, 11, "bold")).pack()
        tk.Label(zone, text=self.t("done_sub"), bg=C["surface"], fg=C["muted"],
                 font=(UI_FONT, 9), wraplength=250).pack(pady=(4, 10))
        again = tk.Button(zone, text=self.t("check_another"), command=self._choose_file,
                          bg=C["surface"], fg=C["accent"], activebackground=C["surface_hover"],
                          activeforeground=C["accent"], relief="flat", bd=0,
                          highlightthickness=1, highlightbackground=C["border"],
                          cursor="hand2", font=(UI_FONT, 9, "bold"), padx=16, pady=6)
        again.pack(pady=(0, 26))
        if DND_AVAILABLE:
            zone.drop_target_register(DND_FILES)
            zone.dnd_bind("<<Drop>>", self._on_drop)

    def _draw_logo(self):
        C = self.C
        canvas = self.logo
        canvas.delete("all")
        accent = C["accent"]
        shield = [17, 3, 30, 8, 30, 19, 17, 33, 4, 19, 4, 8]
        canvas.create_polygon(shield, fill=_lerp(accent, C["bg"], 0.15),
                              outline=accent, width=1.5, joinstyle="round")
        y = 7 + self.logo_scan * 20
        glow = _lerp(accent, "#ffffff", 0.55)
        canvas.create_line(7, y, 27, y, fill=glow, width=2)
        canvas.create_line(10, 18, 15, 23, fill="#ffffff", width=2.4, capstyle="round")
        canvas.create_line(15, 23, 24, 12, fill="#ffffff", width=2.4, capstyle="round")

    def _animate_logo(self):
        if not self.logo.winfo_exists():
            self.logo_job = None
            return
        self.logo_scan += 0.035
        if self.logo_scan > 1.0:
            self.logo_scan = 0.0
        self._draw_logo()
        self.logo_job = self.root.after(40, self._animate_logo)

    def _draw_idle_badge(self, offset):
        C = self.C
        canvas = self.idle_badge
        canvas.delete("all")
        top = 8 + offset
        canvas.create_rectangle(4, top, 52, top + 48, fill=C["chip"], outline="")
        cx = 28
        canvas.create_line(cx, top + 14, cx, top + 30, fill=C["accent"], width=3,
                           capstyle="round")
        canvas.create_line(cx - 7, top + 23, cx, top + 30, fill=C["accent"], width=3,
                           capstyle="round")
        canvas.create_line(cx + 7, top + 23, cx, top + 30, fill=C["accent"], width=3,
                           capstyle="round")
        canvas.create_line(cx - 8, top + 38, cx + 8, top + 38, fill=C["accent"], width=3,
                           capstyle="round")

    def _animate_idle(self):
        if self.stage != "idle" or not self.idle_badge.winfo_exists():
            self.idle_job = None
            return
        self.idle_phase = (self.idle_phase + 0.09) % (2 * math.pi)
        self._draw_idle_badge(round(-3 * math.sin(self.idle_phase), 1))
        self.idle_job = self.root.after(45, self._animate_idle)

    def _animate_spinner(self):
        if self.stage != "checking" or not self.spinner.winfo_exists():
            self.spinner_job = None
            return
        self.spinner_angle = (self.spinner_angle + 11) % 360
        C = self.C
        self.spinner.delete("all")
        self.spinner.create_oval(4, 4, 30, 30, outline=C["border"], width=3)
        self.spinner.create_arc(4, 4, 30, 30, start=self.spinner_angle, extent=100,
                                style="arc", outline=C["accent"], width=3)
        self.spinner_job = self.root.after(40, self._animate_spinner)

    def _btn_hover_on(self, event=None):
        if not self.busy:
            self.choose_btn.config(bg=_lerp(self.C["accent"], "#ffffff", 0.12))

    def _btn_hover_off(self, event=None):
        if not self.busy:
            self.choose_btn.config(bg=self.C["accent"])

    def _zone_hover_on(self, event=None):
        C = self.C
        self.drop_zone.config(highlightbackground=C["accent"], highlightcolor=C["accent"])

    def _zone_hover_off(self, event=None):
        C = self.C
        self.drop_zone.config(highlightbackground=C["border"], highlightcolor=C["border"])

    def _draw_verdict(self, event=None):
        canvas = self.verdict_canvas
        canvas.delete("all")
        width = canvas.winfo_width()
        if width <= 1:
            return
        C = self.C
        canvas.config(bg=C["surface"])
        v = self.current_verdict

        if not v:
            canvas.create_text(24, 40, text=self.t("awaiting_verdict"), fill=C["muted"],
                               font=(UI_FONT, 15, "bold"), anchor="w")
            canvas.create_text(24, 64, text=self.t("awaiting_sub"), fill=C["muted"],
                               font=(UI_FONT, 9), anchor="w")
            return

        color = LEVEL_COLORS[v["level"]]
        canvas.create_text(24, 26, text=self.t("verdict_eyebrow"), fill=C["muted"],
                           font=(UI_FONT, 8, "bold"), anchor="w")
        canvas.create_text(24, 52, text=self.t("level_" + v["level"]), fill=color,
                           font=(UI_FONT, 20, "bold"), anchor="w")
        canvas.create_text(width - 24, 26, text=self.t("score_eyebrow"), fill=C["muted"],
                           font=(UI_FONT, 8, "bold"), anchor="e")
        canvas.create_text(width - 60, 54, text=str(self.score_shown), fill=C["text"],
                           font=(UI_FONT, 22, "bold"), anchor="e")
        canvas.create_text(width - 24, 58, text="/100", fill=C["muted"],
                           font=(UI_FONT, 12), anchor="e")
        track_x0, track_x1 = 24, width - 24
        canvas.create_rectangle(track_x0, 82, track_x1, 88, fill=C["chip"], outline="")
        filled = track_x0 + (track_x1 - track_x0) * self.score_shown / 100
        canvas.create_rectangle(track_x0, 82, filled, 88, fill=color, outline="")

    def _animate_score(self):
        target = self.current_verdict["score"] if self.current_verdict else 0
        if self.score_shown < target:
            step = max(1, round((target - self.score_shown) * 0.18))
            self.score_shown = min(target, self.score_shown + step)
            self._draw_verdict()
            self.root.after(18, self._animate_score)
        else:
            self.score_shown = target
            self._draw_verdict()

    def _render_findings(self):
        C = self.C
        self._cancel_reveal()
        for widget in self.findings.winfo_children():
            widget.destroy()
        self.wrap_labels = [
            (label, pad) for label, pad in self.wrap_labels if label.winfo_exists()
        ]
        self._render_file_card()
        self._render_advice_card()

        v = self.current_verdict
        if not v:
            tk.Label(self.findings, text=self.t("awaiting_sub"), bg=C["bg"], fg=C["muted"],
                     font=(UI_FONT, 9), anchor="w").pack(fill="x")
            return

        cards = list(v["cards"])
        if not cards:
            self._simple_card(self.t("nothing_found"), "info")
        else:
            origin = [c for c in cards if c["key"].startswith(ORIGIN_KEYS)]
            behavior = [c for c in cards if not c["key"].startswith(ORIGIN_KEYS)]
            if origin:
                self._section_header(self.t("section_origin"))
                for card in origin:
                    self._finding_card(card)
            if behavior:
                self._section_header(self.t("section_behavior"), first=not origin)
                for card in behavior:
                    self._finding_card(card)
            if v["analyzed_dynamically"]:
                note = tk.Label(self.findings, bg=C["bg"], fg=C["muted"],
                                text=self.t("checked_dynamic", seconds=config.OBSERVE_SECONDS),
                                font=(UI_FONT, 8), anchor="w", justify="left")
                self.wrap_labels.append((note, 20))
                self.reveal_queue.append((note, {"fill": "x", "pady": (6, 12)}))
        self._reveal_next()

    def _cancel_reveal(self):
        if self.reveal_job is not None:
            self.root.after_cancel(self.reveal_job)
            self.reveal_job = None
        self.reveal_queue = []

    def _reveal_next(self):
        if not self.reveal_queue:
            self.reveal_job = None
            return
        widget, opts = self.reveal_queue.pop(0)
        if widget.winfo_exists():
            widget.pack(**opts)
            self.scroll_canvas.update_idletasks()
            self.scroll_canvas.config(scrollregion=self.scroll_canvas.bbox("all"))
        delay = 55 if self.reveal_queue else 0
        self.reveal_job = self.root.after(delay, self._reveal_next)

    def _section_header(self, text, first=True):
        C = self.C
        label = tk.Label(self.findings, text=text.upper(), bg=C["bg"], fg=C["muted"],
                         font=(UI_FONT, 8, "bold"), anchor="w")
        self.reveal_queue.append((label, {"fill": "x", "pady": (0 if first else 12, 8)}))

    def _card_shell(self, accent):
        C = self.C
        outer = tk.Frame(self.findings, bg=C["border"])
        inner = tk.Frame(outer, bg=C["surface"])
        inner.pack(fill="both", expand=True, padx=(3, 1), pady=1)
        bar = tk.Frame(outer, bg=accent, width=3)
        bar.place(x=0, y=0, relheight=1)
        self.reveal_queue.append((outer, {"fill": "x", "pady": (0, 10)}))
        return outer, inner, accent

    def _bind_card_hover(self, outer, inner, accent):
        C = self.C
        widgets = [inner]
        stack = [inner]
        while stack:
            for child in stack.pop().winfo_children():
                widgets.append(child)
                stack.append(child)
        tinted = [w for w in widgets
                  if isinstance(w, (tk.Frame, tk.Label)) and str(w["bg"]) == C["surface"]]

        def paint(color):
            for widget in tinted:
                if widget.winfo_exists():
                    widget.config(bg=color)

        for widget in widgets:
            widget.bind("<Enter>", lambda e: paint(C["surface_hover"]), add="+")
            widget.bind("<Leave>", lambda e: paint(C["surface"]), add="+")

    def _simple_card(self, text, severity):
        C = self.C
        outer, inner, accent = self._card_shell(SEVERITY_COLORS[severity])
        label = tk.Label(inner, text=text, bg=C["surface"], fg=C["text"],
                         font=(UI_FONT, 10), anchor="w", justify="left")
        label.pack(fill="x", padx=16, pady=14)
        self.wrap_labels.append((label, 60))
        self._bind_card_hover(outer, inner, accent)

    def _finding_card(self, card):
        C = self.C
        severity = card["severity"]
        outer, inner, accent = self._card_shell(SEVERITY_COLORS[severity])

        head = tk.Frame(inner, bg=C["surface"])
        head.pack(fill="x", padx=16, pady=(14, 2))
        tk.Label(head, text=SEVERITY_ICONS[severity], bg=C["surface"], fg=accent,
                 font=(UI_FONT, 10)).pack(side="left", padx=(0, 8))
        tk.Label(head, text=self.t(card["key"], **card["params"]), bg=C["surface"],
                 fg=C["text"], font=(UI_FONT, 10, "bold")).pack(side="left")

        desc = tk.Label(inner, text=self.t(card["key"] + "_desc", **card["params"]),
                        bg=C["surface"], fg=C["muted"], font=(UI_FONT, 9),
                        anchor="w", justify="left")
        desc.pack(fill="x", padx=(40, 16), pady=(0, 12))
        self.wrap_labels.append((desc, 90))

        items = card["params"].get("items")
        if items and card["key"].startswith("cat_"):
            chips = tk.Frame(inner, bg=C["surface"])
            chips.pack(fill="x", padx=(40, 16), pady=(0, 14))
            for marker in items.split(", ")[:5]:
                tk.Label(chips, text=marker, bg=C["chip"], fg=C["report_fg"],
                         font=(MONO_FONT, 8), padx=7, pady=3).pack(side="left", padx=(0, 6))
        self._bind_card_hover(outer, inner, accent)

    def _render_file_card(self):
        C = self.C
        for widget in self.file_card.winfo_children():
            widget.destroy()
        s = self.current_static
        if not s:
            return
        box = tk.Frame(self.file_card, bg=C["surface"], highlightthickness=1,
                       highlightbackground=C["border"])
        box.pack(fill="x")
        tk.Label(box, text=self.t("section_file").upper(), bg=C["surface"], fg=C["muted"],
                 font=(UI_FONT, 8, "bold"), anchor="w").pack(fill="x", padx=14, pady=(12, 6))
        rows = [
            _ellipsis(s["file_name"], 30),
            s["detected_type"],
            self.t("size_bytes", mb=f"{s['file_size'] / (1024 * 1024):.1f}",
                   bytes=s["file_size"]),
        ]
        for index, value in enumerate(rows):
            tk.Label(box, text=value, bg=C["surface"],
                     fg=C["text"] if index == 0 else C["muted"],
                     font=(UI_FONT, 9, "bold" if index == 0 else "normal"),
                     anchor="w").pack(fill="x", padx=14)
        tk.Label(box, text=s["sha256"][:32] + "…", bg=C["surface"], fg=C["muted"],
                 font=(MONO_FONT, 8), anchor="w").pack(fill="x", padx=14, pady=(6, 12))

    def _render_advice_card(self):
        C = self.C
        for widget in self.advice_card.winfo_children():
            widget.destroy()
        v = self.current_verdict
        if not v and not self.notice:
            return
        outer = tk.Frame(self.advice_card, bg=C["border"])
        outer.pack(fill="x")
        inner = tk.Frame(outer, bg=C["surface"])
        inner.pack(fill="both", expand=True, padx=(3, 1), pady=1)
        tk.Frame(outer, bg=C["accent"], width=3).place(x=0, y=0, relheight=1)
        tk.Label(inner, text=self.t("section_advice").upper(), bg=C["surface"], fg=C["muted"],
                 font=(UI_FONT, 8, "bold"), anchor="w").pack(fill="x", padx=14, pady=(12, 6))
        if v:
            text = self.t("advice_" + v["level"], seconds=config.OBSERVE_SECONDS)
            tk.Label(inner, text=text, bg=C["surface"], fg=C["text"], font=(UI_FONT, 9),
                     anchor="w", justify="left", wraplength=250).pack(fill="x", padx=14,
                                                                     pady=(0, 8))
        if self.notice:
            notice = (self.t(self.notice) if i18n.has(self.notice)
                      else self.t("err_generic", err=self.notice))
            tk.Label(inner, text=notice, bg=C["surface"], fg=C["muted"], font=(UI_FONT, 8),
                     anchor="w", justify="left", wraplength=250).pack(fill="x", padx=14,
                                                                     pady=(0, 12))

    def _rebuild(self):
        for job in (self.progress_job, self.spinner_job, self.idle_job, self.logo_job):
            if job is not None:
                self.root.after_cancel(job)
        self.progress_job = None
        self.spinner_job = None
        self.idle_job = None
        self.logo_job = None
        self._cancel_reveal()
        for widget in self.root.winfo_children():
            if not isinstance(widget, tk.Toplevel):
                widget.destroy()
        self._build_ui()
        if self.busy:
            self._start_progress()

    def _open_settings(self):
        if self.settings_win is not None and self.settings_win.winfo_exists():
            self.settings_win.lift()
            return
        win = tk.Toplevel(self.root)
        self.settings_win = win
        win.resizable(False, False)
        win.transient(self.root)
        win.geometry("+%d+%d" % (self.root.winfo_rootx() + 300,
                                 self.root.winfo_rooty() + 140))
        self._render_settings()

    def _render_settings(self):
        win = self.settings_win
        if win is None or not win.winfo_exists():
            return
        C = self.C
        win.title(self.t("settings"))
        win.configure(bg=C["bg"])
        for widget in win.winfo_children():
            widget.destroy()
        body = tk.Frame(win, bg=C["bg"], padx=24, pady=20)
        body.pack(fill="both", expand=True)
        rows = [
            ("lang_label", "language",
             [("uk", i18n.LANGUAGES["uk"]), ("en", i18n.LANGUAGES["en"])]),
            ("theme_label", "theme",
             [("dark", self.t("theme_dark")), ("light", self.t("theme_light"))]),
            ("online_label", "online_check",
             [(True, self.t("online_on")), (False, self.t("online_off"))]),
        ]
        for label_key, setting_key, options in rows:
            row = tk.Frame(body, bg=C["bg"])
            row.pack(fill="x", pady=8)
            tk.Label(row, text=self.t(label_key), bg=C["bg"], fg=C["text"],
                     font=(UI_FONT, 10, "bold"), width=10, anchor="w").pack(side="left")
            for value, title in options:
                active = self.settings[setting_key] == value
                tk.Button(row, text=title,
                          command=lambda k=setting_key, v=value: self._set_setting(k, v),
                          bg=C["accent"] if active else C["surface"],
                          fg="#ffffff" if active else C["text"],
                          activebackground=C["accent_dark"] if active else C["surface_hover"],
                          activeforeground="#ffffff" if active else C["text"],
                          relief="flat", bd=0, highlightthickness=1,
                          highlightbackground=C["accent"] if active else C["border"],
                          cursor="hand2",
                          font=(UI_FONT, 9, "bold" if active else "normal"),
                          padx=16, pady=6).pack(side="left", padx=(0, 8))

        key_row = tk.Frame(body, bg=C["bg"])
        key_row.pack(fill="x", pady=(12, 0))
        tk.Label(key_row, text=self.t("vt_key_label"), bg=C["bg"], fg=C["text"],
                 font=(UI_FONT, 10, "bold"), anchor="w").pack(fill="x")
        tk.Label(key_row, text=self.t("vt_key_hint"), bg=C["bg"], fg=C["muted"],
                 font=(UI_FONT, 8), anchor="w", justify="left",
                 wraplength=360).pack(fill="x", pady=(2, 6))
        entry_row = tk.Frame(key_row, bg=C["bg"])
        entry_row.pack(fill="x")
        self.key_entry = tk.Entry(entry_row, bg=C["surface"], fg=C["text"],
                                  insertbackground=C["text"], relief="flat",
                                  highlightthickness=1, highlightbackground=C["border"],
                                  highlightcolor=C["accent"], font=(MONO_FONT, 9), show="•")
        self.key_entry.insert(0, self.settings.get("vt_key", ""))
        self.key_entry.pack(side="left", fill="x", expand=True, ipady=5)
        tk.Button(entry_row, text=self.t("save_key"), command=self._save_key,
                  bg=C["accent"], fg="#ffffff", activebackground=C["accent_dark"],
                  activeforeground="#ffffff", relief="flat", bd=0, highlightthickness=0,
                  cursor="hand2", font=(UI_FONT, 9, "bold"),
                  padx=14, pady=5).pack(side="left", padx=(8, 0))
        self.key_status = tk.Label(key_row, text="", bg=C["bg"], fg=C["muted"],
                                   font=(UI_FONT, 8), anchor="w")
        self.key_status.pack(fill="x", pady=(6, 0))

    def _save_key(self):
        value = self.key_entry.get().strip()
        self.settings["vt_key"] = value[:128]
        app_settings.save(self.settings)
        self.key_status.config(
            text=self.t("key_saved" if value else "key_cleared"),
            fg=LEVEL_COLORS["clean"] if value else self.C["muted"],
        )

    def _set_setting(self, key, value):
        if self.settings[key] == value:
            return
        self.settings[key] = value
        app_settings.save(self.settings)
        self._rebuild()
        self._render_settings()

    def _choose_file(self):
        path = self._pick_file()
        if path:
            self._start_check(path)

    def _pick_file(self):
        if sys.platform.startswith("linux") and shutil.which("zenity"):
            try:
                proc = subprocess.run(
                    ["zenity", "--file-selection", "--title", self.t("choose_file")],
                    capture_output=True, text=True, timeout=600, env=_native_env(),
                )
                if proc.returncode == 0:
                    return proc.stdout.strip()
                if proc.returncode == 1:
                    return ""
            except (OSError, subprocess.TimeoutExpired):
                pass
        return filedialog.askopenfilename()

    def _on_drop(self, event):
        raw = event.data.strip()
        if raw.startswith("{") and raw.endswith("}"):
            raw = raw[1:-1]
        path = raw.split("} {")[0].strip()
        if os.path.isfile(path):
            self._start_check(path)

    def _start_check(self, path):
        if self.busy:
            return
        size_mb = os.path.getsize(path) / (1024 * 1024)
        if size_mb > config.MAX_FILE_SIZE_MB:
            self.notice = self.t("file_too_big", size=f"{size_mb:.1f}")
            self._render_advice_card()
            return
        self.busy = True
        self.current_verdict = None
        self.current_static = None
        self.notice = ""
        self.stage = "checking"
        self.step_index = 0
        self.checked_name = os.path.basename(path)
        self.score_shown = 0
        self._render_zone()
        self._set_status("status_static")
        self._start_progress()
        self._draw_verdict()
        self._render_findings()
        threading.Thread(target=self._worker, args=(path,), daemon=True).start()

    def _steps(self):
        online = bool(self.settings.get("online_check"))
        return [step for step in ALL_STEPS if online or not step[2]]

    def _status_colors(self):
        if self.busy:
            return self.C["accent"], "#ffffff"
        return LEVEL_COLORS["clean"], "#06301a"

    def _set_status(self, key):
        C = self.C
        self.status_key = key
        bg, fg = self._status_colors()
        self.status.config(text=self.t(key) if i18n.has(key) else key, bg=bg, fg=fg)
        self.choose_btn.config(state="disabled" if self.busy else "normal",
                               bg=C["surface"] if self.busy else C["accent"],
                               fg=C["muted"] if self.busy else "#ffffff",
                               cursor="watch" if self.busy else "hand2")

    def _start_progress(self):
        self.progress.pack(fill="x", pady=(6, 0), after=self.drop_zone)
        if self.progress_job is None:
            self._animate_progress()

    def _stop_progress(self):
        if self.progress_job is not None:
            self.root.after_cancel(self.progress_job)
            self.progress_job = None
        self.progress.delete("all")
        self.progress.pack_forget()

    def _animate_progress(self):
        canvas = self.progress
        if not self.busy or not canvas.winfo_exists():
            self.progress_job = None
            return
        self.progress_job = self.root.after(16, self._animate_progress)
        width = canvas.winfo_width()
        if width <= 1:
            return
        C = self.C
        canvas.delete("all")
        canvas.create_rectangle(0, 0, width, 3, fill=C["chip"], outline="")
        span = width * 0.32
        self.progress_pos = (self.progress_pos + width * 0.013) % (width + span)
        canvas.create_rectangle(max(self.progress_pos - span, 0), 0,
                                min(self.progress_pos, width), 3,
                                fill=C["accent"], outline="")

    def _worker(self, path):
        session = None
        static_result = None
        try:
            self.msg_queue.put(("status", "status_static"))
            static_result = static_analysis.analyze(path)
            self.msg_queue.put(("static", static_result))
            self._add_reputation(static_result)
            session = sandbox_manager.create_session(path)
            report = sandbox_manager.run_sandbox(
                session, progress=lambda m: self.msg_queue.put(("status", m))
            )
            result = verdict.evaluate(static_result, report)
            self._save_report(session, static_result, report, result)
            self.msg_queue.put(("verdict", result))
        except sandbox_manager.SandboxError as e:
            self.msg_queue.put(("error", str(e)))
            if static_result:
                self.msg_queue.put(("verdict", verdict.evaluate(static_result, None)))
        except Exception as e:
            self.msg_queue.put(("error", str(e)))
        finally:
            if session:
                sandbox_manager.cleanup(session)
            self.msg_queue.put(("done", None))

    def _add_reputation(self, static_result):
        if not self.settings.get("online_check"):
            return
        self.msg_queue.put(("status", "status_reputation"))
        static_result["reputation"] = reputation.lookup(
            static_result["sha256"], self.settings.get("vt_key", "")
        )

    def _save_report(self, session, static_result, dynamic_report, result):
        out = {"verdict": result, "static": static_result, "dynamic": dynamic_report}
        path = os.path.join(session["shared"], "full_report.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.msg_queue.get_nowait()
                self._handle(kind, payload)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _handle(self, kind, payload):
        if kind == "status":
            self._set_status(payload if i18n.has(payload) else "ready")
            keys = [key for key, _, _ in self._steps()]
            if payload in keys:
                self.step_index = keys.index(payload)
                self._render_zone()
        elif kind == "static":
            self.current_static = payload
            self._render_file_card()
        elif kind == "verdict":
            self.current_verdict = payload
            self.score_shown = 0
            self._animate_score()
            self._render_findings()
        elif kind == "error":
            self.notice = payload
            self._render_advice_card()
        elif kind == "done":
            self.busy = False
            self.stage = "done"
            self._stop_progress()
            self._render_zone()
            self._set_status("status_done")


def _lerp(color_a, color_b, t):
    a = tuple(int(color_a[i:i + 2], 16) for i in (1, 3, 5))
    b = tuple(int(color_b[i:i + 2], 16) for i in (1, 3, 5))
    mixed = tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))
    return "#%02x%02x%02x" % tuple(max(0, min(255, c)) for c in mixed)


def _ellipsis(text, limit):
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _style_scrollbar(parent, C):
    style = ttk.Style(parent)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("App.Vertical.TScrollbar", background=C["border"],
                    troughcolor=C["bg"], bordercolor=C["bg"], lightcolor=C["bg"],
                    darkcolor=C["bg"], arrowcolor=C["muted"], relief="flat")
    style.map("App.Vertical.TScrollbar",
              background=[("active", C["scroll_active"]), ("pressed", C["accent"])])


def _native_env():
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("SNAP", "GTK_", "GDK_", "GIO_", "VSCODE_"))
        and k not in ("LD_LIBRARY_PATH", "LD_PRELOAD", "LOCPATH", "GSETTINGS_SCHEMA_DIR")
    }
    env["PATH"] = "/usr/bin:/bin:/usr/local/bin"
    for key in ("XDG_DATA_DIRS", "XDG_CONFIG_DIRS"):
        original = os.environ.get(key + "_VSCODE_SNAP_ORIG")
        if original:
            env[key] = original
    return env


def main():
    os.makedirs(config.SESSIONS_DIR, exist_ok=True)
    root = TkinterDnD.Tk() if DND_AVAILABLE else tk.Tk()
    SandCheckApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
