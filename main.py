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


LEVEL_COLORS = {
    "Чистий": "#2e7d32",
    "Підозрілий": "#f57f17",
    "Небезпечний": "#c62828",
}


class FileCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("FileChecker — перевірка файлів у пісочниці")
        self.root.geometry("820x640")
        self.msg_queue = queue.Queue()
        self.busy = False
        self._build_ui()
        self.root.after(100, self._poll_queue)

    def _build_ui(self):
        top = tk.Frame(self.root, padx=12, pady=12)
        top.pack(fill="x")

        self.drop_zone = tk.Label(
            top,
            text="Перетягніть файл сюди\nабо натисніть «Обрати файл»",
            relief="ridge",
            bd=2,
            height=5,
            bg="#eef2f7",
            fg="#333",
            font=("Segoe UI", 11),
        )
        self.drop_zone.pack(fill="x")

        if DND_AVAILABLE:
            self.drop_zone.drop_target_register(DND_FILES)
            self.drop_zone.dnd_bind("<<Drop>>", self._on_drop)

        btns = tk.Frame(top, pady=8)
        btns.pack(fill="x")
        tk.Button(btns, text="Обрати файл", command=self._choose_file).pack(side="left")
        self.status = tk.Label(btns, text="Готовий", fg="#555")
        self.status.pack(side="left", padx=12)

        self.verdict_label = tk.Label(
            self.root, text="", font=("Segoe UI", 16, "bold"), pady=6
        )
        self.verdict_label.pack(fill="x")

        self.report_box = scrolled_text(self.root)
        self.report_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))

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
        color = LEVEL_COLORS.get(v["level"], "#333")
        self.verdict_label.config(
            text=f"Вердикт: {v['level']}  ({v['score']}/100)",
            bg=color,
            fg="white",
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
    frame = tk.Frame(parent)
    frame.pack_propagate(False)
    text = tk.Text(frame, wrap="word", font=("Consolas", 10), state="disabled")
    scroll = ttk.Scrollbar(frame, command=text.yview)
    text.config(yscrollcommand=scroll.set)
    scroll.pack(side="right", fill="y")
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
