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

        self.verdict_label = tk.Label(
            self.root,
            text="",
            bg=C["bg"],
            fg=C["text"],
            font=("Segoe UI", 15, "bold"),
            pady=12,
        )
        self.verdict_label.pack(fill="x", padx=24, pady=(10, 0))

        self.report_box = scrolled_text(self.root, C)
        self.report_box.pack(fill="both", expand=True, padx=24, pady=(12, 22))

        if self.current_verdict:
            self._render_verdict_banner(self.current_verdict)

    def _rebuild(self):
        report_text = self.report_box.get("1.0", "end-1c")
        for widget in self.root.winfo_children():
            if not isinstance(widget, tk.Toplevel):
                widget.destroy()
        self._build_ui()
        self._set_report(report_text)

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
                    timeout=300,
                )
                return proc.stdout.strip() if proc.returncode == 0 else ""
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
        self.verdict_label.config(text="", bg=self.C["bg"])
        self._set_report("")
        self._append(self.t("file_line", name=os.path.basename(path)) + "\n")
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
            self._render_static(payload)
        elif kind == "dynamic":
            self._render_dynamic(payload)
        elif kind == "verdict":
            self._render_verdict(payload)
        elif kind == "error":
            message = self.t(payload) if i18n.has(payload) else self.t("err_generic", err=payload)
            self._append(f"\n[!] {message}\n")
        elif kind == "done":
            self.busy = False
            self.status_key = "ready"
            self.status.config(text=self.t("ready"))

    def _render_static(self, s):
        lines = [
            self.t("static_header"),
            self.t("static_type", type=s["detected_type"], ext=s["extension"]),
            self.t("static_size", size=s["file_size"]),
            f"SHA-256: {s['sha256']}",
            f"MD5: {s['md5']}",
            self.t("static_entropy", value=s["entropy"]),
        ]
        if s["extension_mismatch"]:
            lines.append(self.t("warn_mismatch"))
        if s["double_extension"]:
            lines.append(self.t("warn_double"))
        if s["suspicious_strings"]:
            lines.append(self.t("static_sus", items=", ".join(s["suspicious_strings"])))
        if s["urls"]:
            lines.append(self.t("static_urls", items=", ".join(s["urls"][:10])))
        self._append("\n".join(lines) + "\n")

    def _render_dynamic(self, d):
        lines = ["\n" + self.t("dynamic_header")]
        lines.append(
            self.t(
                "dynamic_launched",
                launched=d.get("launched"),
                seconds=d.get("observed_seconds"),
            )
        )
        fields = [
            ("f_processes", "new_processes"),
            ("f_services", "new_services"),
            ("f_tasks", "new_tasks"),
            ("f_autoruns", "new_autoruns"),
            ("f_files", "new_files"),
            ("f_connections", "new_connections"),
        ]
        for label_key, key in fields:
            vals = d.get(key) or []
            if vals:
                shown = ", ".join(str(v) for v in vals[:15])
                lines.append(f"{self.t(label_key)} ({len(vals)}): {shown}")
        self._append("\n".join(lines) + "\n")

    def _render_verdict(self, v):
        self.current_verdict = v
        self._render_verdict_banner(v)
        lines = ["\n" + self.t("verdict_header")]
        for key, params in v["indicators"]:
            lines.append(" - " + self.t(key, **params))
        if not v["indicators"]:
            lines.append(self.t("no_indicators"))
        self._append("\n".join(lines) + "\n")

    def _render_verdict_banner(self, v):
        color = LEVEL_COLORS.get(v["level"], self.C["border"])
        fg = LEVEL_TEXT_COLORS.get(v["level"], self.C["text"])
        self.verdict_label.config(
            text=self.t("verdict_line", level=self.t("level_" + v["level"]), score=v["score"]),
            bg=color,
            fg=fg,
        )

    def _append(self, text):
        self.report_box.config(state="normal")
        self.report_box.insert("end", text)
        self.report_box.see("end")
        self.report_box.config(state="disabled")

    def _set_report(self, text):
        self.report_box.config(state="normal")
        self.report_box.delete("1.0", "end")
        self.report_box.insert("end", text)
        self.report_box.config(state="disabled")


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
