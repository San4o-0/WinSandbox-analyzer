import json
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

LEVEL_TEXT_COLORS = {
    "clean": "#06301a",
    "suspicious": "#3b2703",
    "dangerous": "#ffffff",
}


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
        self.root.geometry("860x680")
        self.root.minsize(760, 560)
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

        header = tk.Frame(self.root, bg=C["bg"])
        header.pack(fill="x", padx=24, pady=(20, 12))
        logo = tk.Canvas(
            header, width=32, height=32, bg=C["bg"], highlightthickness=0
        )
        logo.create_oval(2, 2, 30, 30, fill=C["accent"], outline="")
        logo.create_line(10, 17, 15, 22, fill="#ffffff", width=3, capstyle="round")
        logo.create_line(15, 22, 23, 11, fill="#ffffff", width=3, capstyle="round")
        logo.pack(side="left", padx=(0, 10), pady=(2, 0))
        tk.Label(
            header,
            text="Sand",
            bg=C["bg"],
            fg=C["text"],
            font=("Segoe UI", 18, "bold"),
        ).pack(side="left")
        tk.Label(
            header,
            text="Check",
            bg=C["bg"],
            fg=C["accent"],
            font=("Segoe UI", 18, "bold"),
        ).pack(side="left")
        tk.Label(
            header,
            text=self.t("subtitle"),
            bg=C["bg"],
            fg=C["muted"],
            font=("Segoe UI", 10),
        ).pack(side="left", padx=(12, 0), pady=(7, 0))
        tk.Button(
            header,
            text="⚙",
            command=self._open_settings,
            bg=C["bg"],
            fg=C["muted"],
            activebackground=C["bg"],
            activeforeground=C["text"],
            relief="flat",
            bd=0,
            highlightthickness=0,
            cursor="hand2",
            font=("Segoe UI", 14),
        ).pack(side="right")

        top = tk.Frame(self.root, bg=C["bg"])
        top.pack(fill="x", padx=24)

        self.drop_zone = tk.Frame(
            top,
            bg=C["surface"],
            bd=0,
            highlightthickness=1,
            highlightbackground=C["border"],
            highlightcolor=C["border"],
        )
        self.drop_zone.pack(fill="x")

        self._zone_icon = tk.Label(
            self.drop_zone,
            text="⬇",
            bg=C["surface"],
            fg=C["accent"],
            font=("Segoe UI", 26, "bold"),
        )
        self._zone_icon.pack(pady=(28, 2))
        self._zone_hint = tk.Label(
            self.drop_zone,
            text=self.t("drop_hint"),
            bg=C["surface"],
            fg=C["text"],
            font=("Segoe UI", 12, "bold"),
        )
        self._zone_hint.pack()
        self._zone_sub = tk.Label(
            self.drop_zone,
            text=self.t("drop_sub"),
            bg=C["surface"],
            fg=C["muted"],
            font=("Segoe UI", 10),
        )
        self._zone_sub.pack(pady=(4, 28))

        self._zone_widgets = (
            self.drop_zone,
            self._zone_icon,
            self._zone_hint,
            self._zone_sub,
        )
        for widget in self._zone_widgets:
            widget.bind("<Enter>", self._zone_hover_on)
            widget.bind("<Leave>", self._zone_hover_off)

        if DND_AVAILABLE:
            for widget in self._zone_widgets:
                widget.drop_target_register(DND_FILES)
                widget.dnd_bind("<<Drop>>", self._on_drop)

        btns = tk.Frame(top, bg=C["bg"])
        btns.pack(fill="x", pady=(14, 4))
        tk.Button(
            btns,
            text=self.t("choose_file"),
            command=self._choose_file,
            bg=C["accent"],
            fg="#ffffff",
            activebackground=C["accent_dark"],
            activeforeground="#ffffff",
            disabledforeground=C["muted"],
            relief="flat",
            bd=0,
            highlightthickness=0,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            padx=20,
            pady=8,
        ).pack(side="left")
        self.status = tk.Label(
            btns,
            text=self.t(self.status_key),
            bg=C["bg"],
            fg=C["muted"],
            font=("Segoe UI", 10),
        )
        self.status.pack(side="left", padx=14)

        self.verdict_canvas = tk.Canvas(
            self.root, height=76, bg=C["bg"], highlightthickness=0
        )
        self.verdict_canvas.pack(fill="x", padx=24, pady=(12, 0))
        self.verdict_canvas.bind("<Configure>", self._draw_verdict)

        self.report_box = scrolled_text(self.root, C)
        self.report_box.pack(fill="both", expand=True, padx=24, pady=(12, 22))
        self._configure_tags()
        self._draw_verdict()
        if self.current_verdict:
            self._render_report()

    def _configure_tags(self):
        C = self.C
        box = self.report_box
        box.tag_configure("section", font=("Segoe UI", 12, "bold"), foreground=C["text"],
                          spacing1=16, spacing3=8)
        box.tag_configure("title", font=("Segoe UI", 10, "bold"), foreground=C["text"],
                          spacing1=8, spacing3=2)
        box.tag_configure("body", font=("Segoe UI", 10), foreground=C["muted"],
                          lmargin1=22, lmargin2=22, spacing3=4)
        box.tag_configure("mono", font=("Consolas", 9), foreground=C["report_fg"],
                          lmargin1=22, lmargin2=22, spacing3=2)
        box.tag_configure("row", font=("Segoe UI", 10), foreground=C["report_fg"],
                          spacing3=3)
        box.tag_configure("note", font=("Segoe UI", 10, "italic"), foreground=C["muted"],
                          spacing1=6, spacing3=6)
        box.tag_configure("advice", font=("Segoe UI", 10), foreground=C["text"],
                          spacing3=6)
        for name, color in (
            ("danger", LEVEL_COLORS["dangerous"]),
            ("warn", LEVEL_COLORS["suspicious"]),
            ("info", C["accent"]),
        ):
            box.tag_configure("dot_" + name, font=("Segoe UI", 11, "bold"), foreground=color)

    def _rebuild(self):
        for widget in self.root.winfo_children():
            if not isinstance(widget, tk.Toplevel):
                widget.destroy()
        self._build_ui()

    def _open_settings(self):
        if self.settings_win is not None and self.settings_win.winfo_exists():
            self.settings_win.lift()
            return
        win = tk.Toplevel(self.root)
        self.settings_win = win
        win.resizable(False, False)
        win.transient(self.root)
        win.geometry(
            "+%d+%d" % (self.root.winfo_rootx() + 240, self.root.winfo_rooty() + 120)
        )
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
            ("lang_label", "language", [("uk", i18n.LANGUAGES["uk"]), ("en", i18n.LANGUAGES["en"])]),
            ("theme_label", "theme", [("dark", self.t("theme_dark")), ("light", self.t("theme_light"))]),
        ]
        for label_key, setting_key, options in rows:
            row = tk.Frame(body, bg=C["bg"])
            row.pack(fill="x", pady=8)
            tk.Label(
                row,
                text=self.t(label_key),
                bg=C["bg"],
                fg=C["text"],
                font=("Segoe UI", 11, "bold"),
                width=10,
                anchor="w",
            ).pack(side="left")
            for value, title in options:
                active = self.settings[setting_key] == value
                tk.Button(
                    row,
                    text=title,
                    command=lambda k=setting_key, v=value: self._set_setting(k, v),
                    bg=C["accent"] if active else C["surface"],
                    fg="#ffffff" if active else C["text"],
                    activebackground=C["accent_dark"] if active else C["surface_hover"],
                    activeforeground="#ffffff" if active else C["text"],
                    relief="flat",
                    bd=0,
                    highlightthickness=1,
                    highlightbackground=C["accent"] if active else C["border"],
                    cursor="hand2",
                    font=("Segoe UI", 10, "bold" if active else "normal"),
                    padx=16,
                    pady=6,
                ).pack(side="left", padx=(0, 8))

    def _set_setting(self, key, value):
        if self.settings[key] == value:
            return
        self.settings[key] = value
        app_settings.save(self.settings)
        self._rebuild()
        self._render_settings()

    def _zone_hover_on(self, event=None):
        C = self.C
        self.drop_zone.config(
            bg=C["surface_hover"],
            highlightbackground=C["accent"],
            highlightcolor=C["accent"],
        )
        self._zone_icon.config(bg=C["surface_hover"])
        self._zone_hint.config(bg=C["surface_hover"])
        self._zone_sub.config(bg=C["surface_hover"])

    def _zone_hover_off(self, event=None):
        C = self.C
        self.drop_zone.config(
            bg=C["surface"],
            highlightbackground=C["border"],
            highlightcolor=C["border"],
        )
        self._zone_icon.config(bg=C["surface"])
        self._zone_hint.config(bg=C["surface"])
        self._zone_sub.config(bg=C["surface"])

    def _choose_file(self):
        path = self._pick_file()
        if path:
            self._start_check(path)

    def _pick_file(self):
        if sys.platform.startswith("linux") and shutil.which("zenity"):
            try:
                proc = subprocess.run(
                    ["zenity", "--file-selection", "--title", self.t("choose_file")],
                    capture_output=True,
                    text=True,
                    timeout=600,
                    env=_native_env(),
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
            self._append(self.t("busy") + "\n")
            return
        size_mb = os.path.getsize(path) / (1024 * 1024)
        if size_mb > config.MAX_FILE_SIZE_MB:
            self._append(self.t("file_too_big", size=f"{size_mb:.1f}") + "\n")
            return
        self.busy = True
        self.current_verdict = None
        self.current_static = None
        self.notice = ""
        self._draw_verdict()
        self._render_report()
        threading.Thread(target=self._worker, args=(path,), daemon=True).start()

    def _worker(self, path):
        session = None
        try:
            self.msg_queue.put(("status", "status_static"))
            static_result = static_analysis.analyze(path)
            self.msg_queue.put(("static", static_result))

            session = sandbox_manager.create_session(path)
            report = sandbox_manager.run_sandbox(
                session, progress=lambda m: self.msg_queue.put(("status", m))
            )

            result = verdict.evaluate(static_result, report)
            self._save_report(session, static_result, report, result)
            self.msg_queue.put(("dynamic", report))
            self.msg_queue.put(("verdict", result))
        except sandbox_manager.SandboxError as e:
            static_result = static_analysis.analyze(path)
            result = verdict.evaluate(static_result, None)
            self.msg_queue.put(("error", str(e)))
            self.msg_queue.put(("verdict", result))
        except Exception as e:
            self.msg_queue.put(("error", str(e)))
        finally:
            if session:
                sandbox_manager.cleanup(session)
            self.msg_queue.put(("done", None))

    def _save_report(self, session, static_result, dynamic_report, result):
        out = {
            "verdict": result,
            "static": static_result,
            "dynamic": dynamic_report,
        }
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
            self.status_key = payload if i18n.has(payload) else "ready"
            self.status.config(text=self.t(payload) if i18n.has(payload) else payload)
        elif kind == "static":
            self.current_static = payload
            self._render_report()
        elif kind == "verdict":
            self.current_verdict = payload
            self._draw_verdict()
            self._render_report()
        elif kind == "error":
            self.notice = (
                self.t(payload) if i18n.has(payload) else self.t("err_generic", err=payload)
            )
            self._render_report()
        elif kind == "done":
            self.busy = False
            self.status_key = "ready"
            self.status.config(text=self.t("ready"))

    def _render_report(self):
        s = self.current_static
        v = self.current_verdict
        box = self.report_box
        box.config(state="normal")
        box.delete("1.0", "end")

        if s:
            self._write(self.t("section_file"), "section")
            rows = [
                (self.t("file_name_row"), s["file_name"]),
                (self.t("file_type_row"), s["detected_type"]),
                (
                    self.t("file_size_row"),
                    self.t(
                        "size_bytes",
                        mb=f"{s['file_size'] / (1024 * 1024):.1f}",
                        bytes=s["file_size"],
                    ),
                ),
            ]
            for label, value in rows:
                self._write(f"{label}: {value}", "row")
            self._write(self.t("file_hash_row") + ":", "row")
            self._write(s["sha256"], "mono")

        if self.notice:
            self._write(self.notice, "note")

        if v:
            static_cards = [c for c in v["cards"] if c["key"] not in i18n.DYNAMIC_KEYS]
            dynamic_cards = [c for c in v["cards"] if c["key"] in i18n.DYNAMIC_KEYS]

            if static_cards:
                self._write(self.t("section_behavior"), "section")
                for card in static_cards:
                    self._write_card(card)

            if v["analyzed_dynamically"]:
                self._write(self.t("section_sandbox"), "section")
                self._write(
                    self.t("checked_dynamic", seconds=config.OBSERVE_SECONDS), "body"
                )
                if dynamic_cards:
                    for card in dynamic_cards:
                        self._write_card(card)
                else:
                    self._write(self.t("nothing_found"), "body")

            self._write(self.t("section_advice"), "section")
            self._write(self.t("advice_" + v["level"], seconds=config.OBSERVE_SECONDS), "advice")
            if not v["analyzed_dynamically"]:
                self._write(self.t("advice_static_only"), "advice")

        box.config(state="disabled")

    def _write(self, text, tag):
        self.report_box.insert("end", text + "\n", tag)

    def _write_card(self, card):
        severity = card["severity"]
        marker = {"danger": "●", "warn": "●", "info": "●"}[severity]
        self.report_box.insert("end", marker + " ", "dot_" + severity)
        self.report_box.insert("end", self.t(card["key"], **card["params"]) + "\n", "title")
        self._write(self.t(card["key"] + "_desc", **card["params"]), "body")
        items = card["params"].get("items")
        if items and card["key"].startswith("cat_"):
            self._write(self.t("found_markers", items=items), "mono")

    def _draw_verdict(self, event=None):
        canvas = self.verdict_canvas
        canvas.delete("all")
        width = canvas.winfo_width()
        if width <= 1:
            return
        C = self.C
        v = self.current_verdict
        if not v:
            canvas.create_rectangle(
                0, 0, width, 76, fill=C["surface"], outline=C["border"]
            )
            canvas.create_text(
                width // 2,
                38,
                text=self.t("drop_sub"),
                fill=C["muted"],
                font=("Segoe UI", 10),
            )
            return

        base = LEVEL_COLORS[v["level"]]
        end = _shade(base, 0.72)
        steps = max(width // 4, 1)
        for i in range(steps):
            x0 = i * width / steps
            canvas.create_rectangle(
                x0, 0, x0 + width / steps + 1, 76,
                fill=_lerp(base, end, i / steps), outline="",
            )
        fg = LEVEL_TEXT_COLORS[v["level"]]
        canvas.create_text(
            22, 26,
            text=self.t("level_" + v["level"]),
            fill=fg, font=("Segoe UI", 16, "bold"), anchor="w",
        )
        canvas.create_text(
            width - 22, 26,
            text=f"{v['score']}/100",
            fill=fg, font=("Segoe UI", 16, "bold"), anchor="e",
        )
        track_x0, track_x1 = 22, width - 22
        canvas.create_rectangle(
            track_x0, 50, track_x1, 58, fill=_shade(base, 0.55), outline=""
        )
        filled = track_x0 + (track_x1 - track_x0) * v["score"] / 100
        canvas.create_rectangle(track_x0, 50, filled, 58, fill=fg, outline="")

    def _append(self, text):
        self.report_box.config(state="normal")
        self.report_box.insert("end", text + "\n", "note")
        self.report_box.see("end")
        self.report_box.config(state="disabled")


def _rgb(color):
    return tuple(int(color[i : i + 2], 16) for i in (1, 3, 5))


def _hex(rgb):
    return "#%02x%02x%02x" % tuple(max(0, min(255, int(c))) for c in rgb)


def _lerp(c1, c2, t):
    a, b = _rgb(c1), _rgb(c2)
    return _hex(a[i] + (b[i] - a[i]) * t for i in range(3))


def _shade(color, factor):
    return _hex(c * factor for c in _rgb(color))


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


def scrolled_text(parent, C):
    style = ttk.Style(parent)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure(
        "App.Vertical.TScrollbar",
        background=C["border"],
        troughcolor=C["surface"],
        bordercolor=C["surface"],
        lightcolor=C["surface"],
        darkcolor=C["surface"],
        arrowcolor=C["muted"],
        relief="flat",
    )
    style.map(
        "App.Vertical.TScrollbar",
        background=[("active", C["scroll_active"]), ("pressed", C["accent"])],
    )
    frame = tk.Frame(
        parent,
        bg=C["surface"],
        bd=0,
        highlightthickness=1,
        highlightbackground=C["border"],
        highlightcolor=C["border"],
    )
    frame.pack_propagate(False)
    text = tk.Text(
        frame,
        wrap="word",
        font=("Consolas", 10),
        state="disabled",
        bg=C["surface"],
        fg=C["report_fg"],
        insertbackground=C["text"],
        selectbackground=C["accent"],
        selectforeground="#ffffff",
        relief="flat",
        bd=0,
        highlightthickness=0,
        padx=14,
        pady=12,
    )
    scroll = ttk.Scrollbar(
        frame, command=text.yview, style="App.Vertical.TScrollbar"
    )
    text.config(yscrollcommand=scroll.set)
    scroll.pack(side="right", fill="y", padx=(0, 2), pady=2)
    text.pack(side="left", fill="both", expand=True)
    text.pack = frame.pack
    return text


def main():
    os.makedirs(config.SESSIONS_DIR, exist_ok=True)
    if DND_AVAILABLE:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    SandCheckApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
