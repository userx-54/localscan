# LocalScan

A local Windows analysis UI with Defender-backed sandbox and signature-analysis modes.

> **Disposable VM only:** run LocalScan in an isolated Windows VM, never on a production machine. Take a snapshot before analysis and restore it afterward.

This student adaptation is based on [`i-vt/LocalScan`](https://github.com/i-vt/LocalScan) and is developed with the original author's permission. Git history and this notice preserve that attribution; project reports should distinguish the original features from student-project changes.

## What it does

- **Sandbox analysis** runs a Defender scan and, unless the scan triggers the skip path, executes the sample while monitoring correlated process, network, Defender, and optional Sysmon events.
- Sandbox results include a deterministic, rule-based dynamic evidence assessment limited to events observed during that run.
- **Signature analysis** locates Defender-triggering bytes, inspects the flagged region, and generates downloadable YARA rules and a patched binary without deliberately executing the sample.
- Both modes calculate file hashes and retain job history across server restarts.
- The localhost-only dark UI supports drag-and-drop upload, progress, result details, history, and downloads; scripted clients can use the same API.

## Safety

- Use a disposable, isolated Windows VM only. Snapshot it before each analysis session and restore it after the session.
- After first-run downloads, use a host-only or isolated NAT adapter; **never use bridged networking**.
- The UI binds to `127.0.0.1` and is intended to be opened inside the VM.
- Samples execute with the server's elevated privileges in Sandbox analysis.
- `uploads`, `results`, and `tmp` under the install directory are excluded from Windows Defender real-time scanning. The launcher directs temporary files to `tmp` for signature analysis.
- Cloud reporting and sample submission are disabled by setup. Keep the VM isolated at the hypervisor level.
- Signature Analysis does not deliberately execute the sample, but processing untrusted data in Defender-excluded paths is not a containment guarantee.
- Dynamic evidence is observational: no observed indicators does not establish absence of malware, VM escape, or other impact.

## Requirements

| Requirement | Notes |
|---|---|
| Windows 10 or 11 (x64) | Disposable VM only |
| Windows Defender | `WinDefend` must be running |
| Python 3.10+ | Setup can install it with `winget` |
| Administrator rights | Needed for setup and Defender/audit configuration |
| Internet access | Needed on first run for Python, Sysmon, and Python packages |
| Sysmon | Optional; adds telemetry when available |

Python dependencies are declared in `requirements.txt`; development tooling is layered through `requirements-dev.txt`.

## Install and run

1. Copy the checkout into the disposable VM, including `install.cmd`, `setup.ps1`, the Python files, `defender_check\`, `templates\`, and the manifests.
2. Double-click `install.cmd` and accept the UAC prompt. If the wrapper cannot be used, open an Administrator PowerShell in the checkout and run `powershell -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1`.
3. Inside the VM, open `http://localhost:5000`.

## Use and API

Choose **Sandbox analysis** or **Signature analysis**, select or drop a file, adjust the mode-specific option, and click **Analyze file**. The UI polls for progress, then shows the mode's result sections; History reopens or deletes prior jobs.

For multipart uploads, send `file`, `mode`, `duration`, and `no_sensitivity` as needed. The application routes are:

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Serve the analysis UI |
| POST | `/api/analyze` | Queue a multipart analysis and return its job ID |
| GET | `/api/status/<job_id>` | Return the live or persisted job |
| GET | `/api/jobs` | List recent job summaries |
| DELETE | `/api/jobs/<job_id>` | Delete a job and its associated files |
| GET | `/api/jobs/<job_id>/patched` | Download the signature-analysis patched binary |
| GET | `/api/jobs/<job_id>/yara` | Download generated YARA rules |

## Architecture

```text
local_scan/
├── install.cmd
├── setup.ps1
├── app.py
├── monitor.py
├── defender_check/
├── templates/index.html
├── requirements.txt
├── requirements-dev.txt
└── tests/
```

`setup.ps1` installs the application source under `C:\MalwareAnalysis` and creates `uploads\`, `results\`, `tmp\`, and `logs\`. One global analysis lock serializes jobs because system-wide snapshots cannot reliably separate concurrent samples. Job JSON is stored in `results\`; signature patched binaries and `.yar` files are written beside the uploaded target in `uploads\` and exposed through the download routes.

## Verify and troubleshoot

For Linux development, run the pytest suite with `.venv/bin/python -m pytest tests/ -v`. On the Windows deployment VM, use `.venv\Scripts\python.exe -m pytest tests\ -v`. For a manual UI check, start the installed server and confirm the page loads at the localhost URL with both mode controls visible; do not execute an untrusted sample merely to verify this guide.

| Symptom | Action |
|---|---|
| Defender unavailable | Ensure the `WinDefend` service is running, then rerun setup. |
| Signature slices quarantined | Confirm `C:\MalwareAnalysis\tmp` is Defender-excluded and use the generated launcher so `TMP`, `TEMP`, and `TMPDIR` point there. |
| Sysmon is missing | Sysmon is optional; install it or continue with reduced telemetry. |
| Sensitivity analysis is slow | Use the Signature analysis option to skip sensitivity analysis when load-bearing-byte details and YARA wildcards are not needed. |
| Dependency download or proxy failure | Restore first-run connectivity or configure the VM's proxy, then rerun setup. |
