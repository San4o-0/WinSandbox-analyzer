import json
import os
import shutil
import subprocess
import time
import uuid

import config


class SandboxError(Exception):
    pass


def _log(msg):
    os.makedirs(config.BASE_DIR, exist_ok=True)
    with open(config.LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")


def _analyzer_source():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "sandbox", "analyzer.ps1")


def _build_wsb(session_dir, shared_dir):
    net = "Enable" if config.SANDBOX_NETWORKING else "Disable"
    logon = (
        "powershell.exe -ExecutionPolicy Bypass -File "
        + config.SANDBOX_SHARED
        + r"\analyzer.ps1"
    )
    wsb = f"""<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{shared_dir}</HostFolder>
      <SandboxFolder>{config.SANDBOX_SHARED}</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <Networking>{net}</Networking>
  <MemoryInMB>{config.SANDBOX_MEMORY_MB}</MemoryInMB>
  <LogonCommand>
    <Command>{logon}</Command>
  </LogonCommand>
</Configuration>
"""
    path = os.path.join(session_dir, "sandbox.wsb")
    with open(path, "w", encoding="utf-8") as f:
        f.write(wsb)
    return path


def create_session(file_path):
    session_id = uuid.uuid4().hex[:12]
    session_dir = os.path.join(config.SESSIONS_DIR, session_id)
    shared_dir = os.path.join(session_dir, "shared")
    os.makedirs(shared_dir, exist_ok=True)

    file_name = os.path.basename(file_path)
    shutil.copy2(file_path, os.path.join(shared_dir, file_name))
    shutil.copy2(_analyzer_source(), os.path.join(shared_dir, "analyzer.ps1"))

    run_cfg = {"file_name": file_name, "observe_seconds": config.OBSERVE_SECONDS}
    with open(os.path.join(shared_dir, "run.json"), "w", encoding="utf-8") as f:
        json.dump(run_cfg, f)

    wsb_path = _build_wsb(session_dir, shared_dir)
    return {
        "id": session_id,
        "dir": session_dir,
        "shared": shared_dir,
        "wsb": wsb_path,
        "report": os.path.join(shared_dir, "report.json"),
    }


def run_sandbox(session, progress=None):
    if shutil.which("WindowsSandbox.exe") is None and not os.path.exists(
        r"C:\Windows\System32\WindowsSandbox.exe"
    ):
        raise SandboxError(
            "Windows Sandbox не знайдено. Увімкніть компонент 'Windows Sandbox'."
        )

    _log(f"Запуск пісочниці для сесії {session['id']}")
    if progress:
        progress("Запуск Windows Sandbox...")

    try:
        subprocess.Popen(["WindowsSandbox.exe", session["wsb"]])
    except FileNotFoundError:
        subprocess.Popen(
            [r"C:\Windows\System32\WindowsSandbox.exe", session["wsb"]]
        )

    report_path = session["report"]
    deadline = time.time() + config.REPORT_TIMEOUT_SECONDS
    if progress:
        progress("Аналіз у віртуальному середовищі...")

    while time.time() < deadline:
        if os.path.exists(report_path):
            time.sleep(2)
            try:
                with open(report_path, "r", encoding="utf-8-sig") as f:
                    report = json.load(f)
                _log(f"Звіт отримано для сесії {session['id']}")
                _close_sandbox()
                return report
            except (json.JSONDecodeError, OSError):
                time.sleep(2)
                continue
        time.sleep(3)

    _close_sandbox()
    raise SandboxError("Час очікування звіту вичерпано.")


def _close_sandbox():
    subprocess.run(
        ["taskkill", "/IM", "WindowsSandboxClient.exe", "/F"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def cleanup(session):
    try:
        shutil.rmtree(session["dir"], ignore_errors=True)
    except OSError:
        pass
