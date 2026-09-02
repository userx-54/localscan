"""Deterministic, verification-only Flask server for the LocalScan UI.

This module is intentionally not imported by the application and is never
installed. Run it with ``python -m tests.ui_fixture_server`` while exercising
the browser checklist. All samples and telemetry below are invented and safe.
"""
from __future__ import annotations

import os
import tempfile
import time
from datetime import datetime, timedelta, timezone

import app as webapp

FIXTURE_IDS = (
    "ui-inconclusive",
    "ui-none",
    "ui-activity",
    "ui-suspicious",
    "ui-defender",
    "ui-skipped",
    "ui-signature-zero",
    "ui-signature-multi",
)


def _scan(filename: str, verdict: str = "clean", threats: list[str] | None = None) -> dict:
    return {
        "filename": filename,
        "filesize": 4096,
        "magic": "ASCII text, with UTF-8 text",
        "hashes": {
            "md5": "11111111111111111111111111111111",
            "sha1": "2222222222222222222222222222222222222222",
            "sha256": "3333333333333333333333333333333333333333333333333333333333333333",
        },
        "verdict": verdict,
        "threats": threats or [],
        "raw_output": "LocalScan UI fixture output; no real file was executed.",
    }


def _assessment(status: str, label: str, reasons: list[str], *, disclaimer: str | None = None) -> dict:
    return {
        "status": status,
        "label": label,
        "reasons": reasons,
        "disclaimer": disclaimer
        or "Fixture data: rule-based observation, not a probability or malware verdict.",
    }


def _monitor(assessment: dict, *, processes=None, connections=None, alerts=None, timeline=None, coverage=None) -> dict:
    return {
        "assessment": assessment,
        "actual_duration": 5,
        "sample_pid": 4242,
        "sysmon_available": True,
        "coverage": coverage or {
            "processes": {"status": "available"},
            "connections": {"status": "available"},
            "defender_events": {"status": "available"},
            "sysmon_events": {"status": "available"},
        },
        "new_processes": processes or [],
        "new_connections": connections or [],
        "defender_alerts": alerts or [],
        "timeline": timeline or [],
    }


def _base_job(job_id: str, filename: str, mode: str = "sandbox", *, submitted_at: str) -> dict:
    return {
        "job_id": job_id,
        "filename": filename,
        "filepath": "",
        "mode": mode,
        "duration": 5,
        "no_sensitivity": False,
        "status": "complete",
        "phase": "Done",
        "submitted_at": submitted_at,
        "completed_at": submitted_at,
        "scan_result": _scan(filename),
        "monitor_result": None,
        "signature_result": None,
        "patched_file_path": None,
        "yara_file_path": None,
        "skip_execution": False,
    }


def seed_jobs(download_dir: str) -> None:
    """Seed the real app's in-memory store with safe, deterministic jobs."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    webapp.jobs.clear()
    for index, job_id in enumerate(FIXTURE_IDS):
        submitted_at = (now - timedelta(minutes=index)).isoformat()
        mode = "signature" if job_id.startswith("ui-signature") else "sandbox"
        job = _base_job(job_id, f"fixture-{job_id.removeprefix('ui-')}.txt", mode, submitted_at=submitted_at)

        if job_id == "ui-inconclusive":
            job["monitor_result"] = _monitor(
                _assessment("inconclusive", "Inconclusive", ["Coverage degraded: process telemetry unavailable"]),
                coverage={
                    "processes": {"status": "degraded"},
                    "connections": {"status": "unavailable"},
                    "defender_events": {"status": "unavailable"},
                    "sysmon_events": {"status": "unavailable"},
                },
            )
        elif job_id == "ui-none":
            job["monitor_result"] = _monitor(
                _assessment("no_correlated_indicators_observed", "No correlated indicators observed", []),
            )
        elif job_id == "ui-activity":
            job["monitor_result"] = _monitor(
                _assessment("activity_observed", "Activity observed", ["Correlated process and network activity observed"]),
                processes=[{"time": 1, "pid": 4243, "ppid": 4242, "name": "fixture-helper.exe", "cmdline": "fixture-helper.exe --safe", "exe": "C:\\Fixture\\fixture-helper.exe", "indicator_class": "none"}],
                connections=[{"time": 2, "laddr": "127.0.0.1:40100", "raddr": "192.0.2.10:443", "status": "ESTABLISHED", "pid": 4243}],
                timeline=[{"time": 1, "type": "process_start", "data": "fixture-helper.exe"}, {"time": 2, "type": "network_connection", "data": "192.0.2.10:443"}],
            )
        elif job_id == "ui-suspicious":
            job["monitor_result"] = _monitor(
                _assessment("suspicious_indicators_observed", "Suspicious indicators observed", ["A process name matched the configured indicator classification"]),
                processes=[{"time": 1, "pid": 4243, "ppid": 4242, "name": "powershell.exe", "cmdline": "powershell.exe -NoProfile", "exe": "C:\\Fixture\\powershell.exe", "indicator_class": "suspicious_process_name"}],
                timeline=[{"time": 1, "type": "process_start", "data": "powershell.exe (classified by backend evidence)"}],
            )
        elif job_id == "ui-defender":
            job["monitor_result"] = _monitor(
                _assessment("defender_detection_observed", "Defender detection observed", ["Runtime Defender detection was correlated to the sample process tree"]),
                alerts=[{"source": "fixture-defender", "message": "Synthetic detection for UI verification", "pid": 4242}],
                timeline=[{"time": 3, "type": "defender_alert", "data": "Synthetic detection for UI verification"}],
            )
        elif job_id == "ui-skipped":
            job["scan_result"] = _scan("fixture-skipped.txt", "threat_detected", ["Fixture.Static.Test"])
            job["skip_execution"] = True
            job["phase"] = "Threat detected during static scan — sandbox execution skipped."
            job["monitor_result"] = _monitor(
                _assessment("defender_detection_observed", "Defender detection observed", ["Static Defender detection prevented execution"]),
                coverage={
                    "processes": {"status": "unavailable"},
                    "connections": {"status": "unavailable"},
                    "defender_events": {"status": "unavailable"},
                    "sysmon_events": {"status": "unavailable"},
                },
            )
        elif job_id == "ui-signature-zero":
            job["signature_result"] = {"hits": [], "clean_after_patching": None}
        elif job_id == "ui-signature-multi":
            patched = os.path.join(download_dir, "fixture-multi-patched.bin")
            yara = os.path.join(download_dir, "fixture-multi-signatures.yar")
            with open(patched, "wb") as handle:
                handle.write(b"safe fixture patched bytes\n")
            with open(yara, "w", encoding="utf-8") as handle:
                handle.write("rule fixture_ui_multi { strings: $a = { 41 42 43 } condition: $a }\n")
            job["signature_result"] = {
                "hits": [
                    {"index": 0, "offset": 12, "offset_hex": "0x0000000C", "entropy": 4.25, "entropy_note": "ordinary text", "signature": "Fixture.Pattern.One", "pe_section": ".text", "flagged_bytes_hex": "41 42 43", "load_bearing_offsets": [1], "strings": ["fixture-one"], "yara_rule": "rule fixture_ui_one { condition: true }"},
                    {"index": 1, "offset": 80, "offset_hex": "0x00000050", "entropy": 6.1, "entropy_note": "mixed fixture bytes", "signature": "Fixture.Pattern.Two", "pe_section": ".rdata", "flagged_bytes_hex": "44 45 46", "load_bearing_offsets": [0, 2], "strings": ["fixture-two"], "yara_rule": "rule fixture_ui_two { condition: true }"},
                ],
                "clean_after_patching": True,
            }
            job["patched_file_path"] = patched
            job["yara_file_path"] = yara
        webapp.jobs[job_id] = job


def fixture_run_analysis(job_id: str, filepath: str, duration: int, mode: str, no_sensitivity: bool) -> None:
    """Safe replacement for app.run_analysis used only by this fixture server."""
    job = webapp.jobs[job_id]
    job["filepath"] = filepath
    job["duration"] = duration
    job["mode"] = mode
    job["no_sensitivity"] = no_sensitivity
    statuses = ["scanning", "analyzing"] if mode == "signature" else ["scanning", "executing"]
    for status in statuses:
        job["status"] = status
        job["phase"] = "Fixture verification: " + status
        webapp._persist_job(job_id)
        time.sleep(0.5)
    job["status"] = "complete"
    job["phase"] = "Fixture verification complete"
    job["completed_at"] = datetime.now(timezone.utc).isoformat()
    if mode == "signature":
        job["signature_result"] = {"hits": [], "clean_after_patching": None}
    else:
        job["monitor_result"] = _monitor(_assessment("no_correlated_indicators_observed", "No correlated indicators observed", []))
    webapp._persist_job(job_id)


def run_fixture_server() -> None:
    """Configure temporary artifacts, seed jobs, then serve the real Flask app."""
    with tempfile.TemporaryDirectory(prefix="localscan-ui-") as root:
        upload_dir = os.path.join(root, "uploads")
        results_dir = os.path.join(root, "results")
        download_dir = os.path.join(root, "downloads")
        os.makedirs(upload_dir)
        os.makedirs(results_dir)
        os.makedirs(download_dir)
        webapp.UPLOAD_DIR = upload_dir
        webapp.RESULTS_DIR = results_dir
        webapp.run_analysis = fixture_run_analysis
        seed_jobs(download_dir)
        print("LocalScan UI fixture server: http://127.0.0.1:5000")
        webapp.app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)


if __name__ == "__main__":
    run_fixture_server()
