# FileChecker

A Windows application: drop a file and it is analyzed inside an isolated virtual environment (Windows Sandbox) without ever running on your host system.

## What it does

1. Static analysis on the host (no execution): hashes, entropy, type by signature, suspicious strings/API calls, extension mismatch, double extensions.
2. Dynamic analysis in Windows Sandbox: system snapshot "before" → launch the file → snapshot "after" → diff (new processes, services, tasks, autoruns, files, network connections).
3. Verdict: Clean / Suspicious / Dangerous with a 0–100 score.

After the analysis, the sandbox is destroyed along with all its changes.

## Requirements

- Windows 10/11 Pro / Enterprise / Education.
- The **Windows Sandbox** feature enabled:
  ```powershell
  Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -All
  ```
- Hardware virtualization (VT-x/AMD-V) enabled in BIOS/UEFI.
- Python 3.10+.

## Installation

```powershell
pip install -r requirements.txt
```

`tkinterdnd2` is only needed for drag & drop. Without it the app still works via the "Choose file" button.

## Run

```powershell
python main.py
```

## Configuration

`config.py`: file size limit, sandbox memory, networking (disabled by default), observation time, report timeout.

## Limitations

- Only one Windows Sandbox instance can run at a time — files are processed sequentially.
- Monitoring is done at the PowerShell level; malware with anti-VM techniques may stay dormant.
- This is a first-pass assessment tool, not a replacement for antivirus software.
