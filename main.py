import json
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, ttk

import config
import sandbox_manager
import static_analysis
import verdict

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD

    DND_AVAILABLE = True
except ImportError:
    DND_AVAILABLE = False


BG = "#0f1115"
SURFACE = "#171a21"
SURFACE_HOVER = "#1d222c"
BORDER = "#2a2f3a"
ACCENT = "#4f8cff"
ACCENT_DARK = "#3d74e0"
TEXT = "#e8ebf1"
MUTED = "#8b93a3"
REPORT_FG = "#c9d1de"

LEVEL_COLORS = {
    "Чистий": "#22c55e",
    "Підозрілий": "#f59e0b",
    "Небезпечний": "#ef4444",
}

LEVEL_TEXT_COLORS = {
    "Чистий": "#06301a",
    "Підозрілий": "#3b2703",
    "Небезпечний": "#ffffff",
}


class FileCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("FileChecker — перевірка файлів у пісочниці")
        self.root.geometry("860x680")
        self.root.minsize(760, 560)
        self.root.configure(bg=BG)
        self.msg_queue = queue.Queue()
        self.busy = False
        self._build_ui()
        self.root.after(100, self._poll_queue)

    def _build_ui(self):
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=24, pady=(20, 12))
        tk.Label(
            header,
            text="FileChecker",
            bg=BG,
            fg=TEXT,
            font=("Segoe UI", 18, "bold"),
        ).pack(side="left")
        tk.Label(
            header,
            text="перевірка файлів у пісочниці",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 10),
        ).pack(side="left", padx=(12, 0), pady=(7, 0))

        top = tk.Frame(self.root, bg=BG)
        top.pack(fill="x", padx=24)

        self.drop_zone = tk.Frame(
            top,
            bg=SURFACE,
            bd=0,
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=BORDER,
        )
        self.drop_zone.pack(fill="x")

        self._zone_icon = tk.Label(
            self.drop_zone,
            text="⬇",
            bg=SURFACE,
            fg=ACCENT,
            font=("Segoe UI", 26, "bold"),
        )
        self._zone_icon.pack(pady=(28, 2))
        self._zone_hint = tk.Label(
            self.drop_zone,
            text="Перетягніть файл сюди",
            bg=SURFACE,
            fg=TEXT,
            font=("Segoe UI", 12, "bold"),
        )
        self._zone_hint.pack()
        self._zone_sub = tk.Label(
            self.drop_zone,
            text="або натисніть «Обрати файл»",
            bg=SURFACE,
            fg=MUTED,
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

        btns = tk.Frame(top, bg=BG)
        btns.pack(fill="x", pady=(14, 4))
        tk.Button(
            btns,
            text="Обрати файл",
            command=self._choose_file,
            bg=ACCENT,
            fg="#ffffff",
            activebackground=ACCENT_DARK,
            activeforeground="#ffffff",
            disabledforeground=MUTED,
            relief="flat",
            bd=0,
            highlightthickness=0,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            padx=20,
            pady=8,
        ).pack(side="left")
        self.status = tk.Label(
            btns, text="Готовий", bg=BG, fg=MUTED, font=("Segoe UI", 10)
        )
        self.status.pack(side="left", padx=14)

        self.verdict_label = tk.Label(
            self.root,
            text="",
            bg=BG,
            fg=TEXT,
            font=("Segoe UI", 15, "bold"),
            pady=12,
        )
        self.verdict_label.pack(fill="x", padx=24, pady=(10, 0))

        self.report_box = scrolled_text(self.root)
        self.report_box.pack(fill="both", expand=True, padx=24, pady=(12, 22))

    def _zone_hover_on(self, event=None):
        self.drop_zone.config(
            bg=SURFACE_HOVER, highlightbackground=ACCENT, highlightcolor=ACCENT
        )
        self._zone_icon.config(bg=SURFACE_HOVER)
        self._zone_hint.config(bg=SURFACE_HOVER)
        self._zone_sub.config(bg=SURFACE_HOVER)

    def _zone_hover_off(self, event=None):
        self.drop_zone.config(
            bg=SURFACE, highlightbackground=BORDER, highlightcolor=BORDER
        )
        self._zone_icon.config(bg=SURFACE)
        self._zone_hint.config(bg=SURFACE)
        self._zone_sub.config(bg=SURFACE)

    def _choose_file(self):
        path = filedialog.askopenfilename()
        if path:
            self._start_check(path)

    def _on_drop(self, event):
        raw = event.data.strip()
        if raw.startswith("{") and raw.endswith("}"):
            raw = raw[1:-1]
        path = raw.split("} {")[0].strip()
        if os.path.isfile(path):
            self._start_check(path)

    def _start_check(self, path):
        if self.busy:
            self._append("Зачекайте: триває перевірка іншого файлу.\n")
            return
        size_mb = os.path.getsize(path) / (1024 * 1024)
        if size_mb > config.MAX_FILE_SIZE_MB:
            self._append(f"Файл завеликий ({size_mb:.1f} МБ).\n")
            return
        self.busy = True
        self.verdict_label.config(text="", bg=self.root["bg"])
        self._set_report("")
        self._append(f"Файл: {os.path.basename(path)}\n")
        threading.Thread(target=self._worker, args=(path,), daemon=True).start()

    def _worker(self, path):
        session = None
        try:
            self.msg_queue.put(("status", "Статичний аналіз..."))
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
            self.msg_queue.put(("error", f"Помилка: {e}"))
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
            self.status.config(text=payload)
        elif kind == "static":
            self._render_static(payload)
        elif kind == "dynamic":
            self._render_dynamic(payload)
        elif kind == "verdict":
            self._render_verdict(payload)
        elif kind == "error":
            self._append(f"\n[!] {payload}\n")
        elif kind == "done":
            self.busy = False
            self.status.config(text="Готовий")

    def _render_static(self, s):
        lines = [
            "=== Статичний аналіз ===",
            f"Тип: {s['detected_type']}   Розширення: {s['extension']}",
            f"Розмір: {s['file_size']} байт",
            f"SHA-256: {s['sha256']}",
            f"MD5: {s['md5']}",
            f"Ентропія: {s['entropy']}",
        ]
        if s["extension_mismatch"]:
            lines.append("[!] Розширення не відповідає типу файлу")
        if s["double_extension"]:
            lines.append("[!] Подвійне розширення")
        if s["suspicious_strings"]:
            lines.append("Підозрілі рядки: " + ", ".join(s["suspicious_strings"]))
        if s["urls"]:
            lines.append("URL: " + ", ".join(s["urls"][:10]))
        self._append("\n".join(lines) + "\n")

    def _render_dynamic(self, d):
        lines = ["\n=== Динамічний аналіз (пісочниця) ==="]
        lines.append(f"Запущено: {d.get('launched')}   Спостереження: {d.get('observed_seconds')} с")
        fields = [
            ("Нові процеси", "new_processes"),
            ("Нові служби", "new_services"),
            ("Нові завдання", "new_tasks"),
            ("Зміни автозапуску", "new_autoruns"),
            ("Нові файли", "new_files"),
            ("Мережеві з'єднання", "new_connections"),
        ]
        for label, key in fields:
            vals = d.get(key) or []
            if vals:
                shown = ", ".join(str(v) for v in vals[:15])
                lines.append(f"{label} ({len(vals)}): {shown}")
        self._append("\n".join(lines) + "\n")

    def _render_verdict(self, v):
        color = LEVEL_COLORS.get(v["level"], BORDER)
        fg = LEVEL_TEXT_COLORS.get(v["level"], TEXT)
        self.verdict_label.config(
            text=f"Вердикт: {v['level']}  ({v['score']}/100)",
            bg=color,
            fg=fg,
        )
        lines = ["\n=== Вердикт ==="]
        for ind in v["indicators"]:
            lines.append(" - " + ind)
        if not v["indicators"]:
            lines.append("Підозрілої активності не виявлено.")
        self._append("\n".join(lines) + "\n")

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


def scrolled_text(parent):
    style = ttk.Style(parent)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure(
        "Dark.Vertical.TScrollbar",
        background=BORDER,
        troughcolor=SURFACE,
        bordercolor=SURFACE,
        lightcolor=SURFACE,
        darkcolor=SURFACE,
        arrowcolor=MUTED,
        relief="flat",
    )
    style.map(
        "Dark.Vertical.TScrollbar",
        background=[("active", "#3a4150"), ("pressed", ACCENT)],
    )
    frame = tk.Frame(
        parent,
        bg=SURFACE,
        bd=0,
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=BORDER,
    )
    frame.pack_propagate(False)
    text = tk.Text(
        frame,
        wrap="word",
        font=("Consolas", 10),
        state="disabled",
        bg=SURFACE,
        fg=REPORT_FG,
        insertbackground=TEXT,
        selectbackground=ACCENT,
        selectforeground="#ffffff",
        relief="flat",
        bd=0,
        highlightthickness=0,
        padx=14,
        pady=12,
    )
    scroll = ttk.Scrollbar(
        frame, command=text.yview, style="Dark.Vertical.TScrollbar"
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
    FileCheckerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
