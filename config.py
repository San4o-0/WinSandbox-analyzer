import os

APP_NAME = "SandCheck"
BASE_DIR = os.path.join(os.path.expanduser("~"), "SandCheck")
SESSIONS_DIR = os.path.join(BASE_DIR, "sessions")
LOG_FILE = os.path.join(BASE_DIR, "sandcheck.log")

MAX_FILE_SIZE_MB = 500
SANDBOX_MEMORY_MB = 2048
SANDBOX_NETWORKING = False
OBSERVE_SECONDS = 60
REPORT_TIMEOUT_SECONDS = 300

SANDBOX_DESKTOP = r"C:\Users\WDAGUtilityAccount\Desktop"
SANDBOX_SHARED = SANDBOX_DESKTOP + r"\shared"

SUSPICIOUS_STRINGS = [
    "VirtualAlloc", "VirtualProtect", "CreateRemoteThread", "WriteProcessMemory",
    "ReadProcessMemory", "OpenProcess", "SetWindowsHookEx", "GetAsyncKeyState",
    "URLDownloadToFile", "WinExec", "ShellExecute", "RegSetValue",
    "AdjustTokenPrivileges", "IsDebuggerPresent", "NtUnmapViewOfSection",
    "powershell -e", "powershell.exe -enc", "-EncodedCommand", "FromBase64String",
    "Invoke-Expression", "IEX(", "DownloadString", "bitsadmin", "certutil -decode",
    "vssadmin delete", "wevtutil cl", "bcdedit /set", "schtasks /create",
    "cmd.exe /c", "wscript.exe", "mshta", "rundll32",
]

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".msi", ".bat", ".cmd",
    ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".jar", ".lnk",
}

MAGIC_SIGNATURES = [
    (b"MZ", "PE (Windows executable)"),
    (b"\x7fELF", "ELF (Linux executable)"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"%PDF", "PDF document"),
    (b"\xd0\xcf\x11\xe0", "OLE document (MS Office legacy)"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"#!", "Script (shebang)"),
]
