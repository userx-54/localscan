"""
app.py — LocalScan Flask API + web UI.

Two analysis modes share the same job lifecycle and UI:

  Sandbox mode  (mode="sandbox", default)
    Phase 1 — static scan via Windows Defender (defender_check.scanner.scan_with_defender)
    Phase 2 — dynamic execution monitoring     (monitor.execute_and_monitor)

  Signature mode  (mode="signature")
    Phase 1 — static scan (hashes, initial verdict)
    Phase 2 — DefenderCheck signature analysis (binary search → sensitivity
              → YARA generation, defender_check.orchestrator.analyse)

API endpoints
-------------
  POST   /api/analyze              submit a file; returns {job_id}
  GET    /api/status/<job_id>      poll for results
  GET    /api/jobs                 list recent jobs (summary)
  DELETE /api/jobs/<job_id>        delete job + uploaded file
  GET    /api/jobs/<job_id>/patched   download patched binary (signature mode)
  GET    /api/jobs/<job_id>/yara      download YARA rules     (signature mode)
"""

import json
import os
import threading
import uuid
from dataclasses import asdict
from datetime import datetime

from flask import Flask, abort, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR  = os.path.join(BASE_DIR, "uploads")
RESULTS_DIR = os.path.join(BASE_DIR, "results")

for _d in (UPLOAD_DIR, RESULTS_DIR):
    os.makedirs(_d, exist_ok=True)

app = Flask(__name__, template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MB

# In-memory job store {job_id: job_dict}; reloaded from disk on startup.
jobs: dict = {}

# Only one analysis runs at a time. System-wide process and event snapshots
# cannot reliably separate telemetry from concurrent samples.
analysis_lock = threading.Lock()


# ── Persistence ───────────────────────────────────────────────────────────────

_LEGACY_ASSESSMENT_DISCLAIMER = (
    "Rule-based observation, not a probability or malware verdict. It covers "
    "only events observed during this run and attributed to the sample process "
    "tree. No observed indicators does not mean the file is safe."
)


def _migrate_legacy_job(job):
    """Convert pre-assessment monitor results without reinterpreting them."""
    monitor_result = job.get("monitor_result")
    if not isinstance(monitor_result, dict):
        return False
    had_legacy_score = "risk_score" in monitor_result
    had_legacy_level = "risk_level" in monitor_result
    if not (had_legacy_score or had_legacy_level):
        return False
    monitor_result.pop("risk_score", None)
    monitor_result.pop("risk_level", None)
    if had_legacy_score and "assessment" not in monitor_result:
        monitor_result["assessment"] = {
            "status": "inconclusive",
            "label": "Inconclusive",
            "reasons": ["Legacy result used uncorrelated telemetry and cannot be reassessed"],
            "disclaimer": _LEGACY_ASSESSMENT_DISCLAIMER,
        }
    return True


def _load_results_from_disk():
    for fname in os.listdir(RESULTS_DIR):
        if fname.endswith(".json"):
            try:
                with open(os.path.join(RESULTS_DIR, fname)) as fh:
                    job = json.load(fh)
                    jobs[job["job_id"]] = job
                    if _migrate_legacy_job(job):
                        _persist_job(job["job_id"])
            except Exception:
                pass

def _persist_job(job_id: str):
    try:
        path = os.path.join(RESULTS_DIR, f"{job_id}.json")
        with open(path, "w") as fh:
            json.dump(jobs[job_id], fh, indent=2, default=str)
    except Exception:
        pass


# ── Analysis pipelines ────────────────────────────────────────────────────────

def _run_sandbox(job_id: str, filepath: str, duration: int):
    """Phase 1: static scan. Phase 2: dynamic execution."""
    from defender_check.scanner import scan_with_defender
    from monitor import execute_and_monitor

    try:
        jobs[job_id]["status"] = "scanning"
        jobs[job_id]["phase"]  = "Running Windows Defender scan…"
        _persist_job(job_id)

        scan_result = scan_with_defender(filepath)
        jobs[job_id]["scan_result"] = scan_result

        if scan_result.get("verdict") == "threat_detected":
            jobs[job_id]["skip_execution"] = True
            jobs[job_id]["phase"] = (
                "Threat detected during static scan — skipping live execution "
                "(file may have been quarantined). Toggle DisableRemediation in "
                "defender_check/scanner.py to execute anyway."
            )

        if not jobs[job_id].get("skip_execution"):
            jobs[job_id]["status"] = "executing"
            jobs[job_id]["phase"]  = f"Executing sample and monitoring for {duration}s…"
            _persist_job(job_id)

            monitor_result = execute_and_monitor(filepath, duration)
            jobs[job_id]["monitor_result"] = monitor_result
        else:
            jobs[job_id]["monitor_result"] = None

        jobs[job_id]["status"]       = "complete"
        jobs[job_id]["phase"]        = "Done"
        jobs[job_id]["completed_at"] = datetime.now().isoformat()

    except Exception as e:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["phase"]  = f"Internal error: {e}"

    _persist_job(job_id)


def _run_signature(job_id: str, filepath: str, no_sensitivity: bool):
    """
    Phase 1: static scan (hashes + verdict).
    Phase 2: DefenderCheck binary-search signature analysis.
    """
    from defender_check.scanner import scan_with_defender
    from defender_check.scanner import configure, locate_mpcmdrun
    from defender_check.orchestrator import analyse

    try:
        # Phase 1 — static scan for hashes / initial verdict
        jobs[job_id]["status"] = "scanning"
        jobs[job_id]["phase"]  = "Running Windows Defender scan…"
        _persist_job(job_id)

        scan_result = scan_with_defender(filepath)
        jobs[job_id]["scan_result"] = scan_result

        # Phase 2 — signature analysis (only useful when Defender flags the file)
        jobs[job_id]["status"] = "analyzing"
        sens_note = " (sensitivity analysis disabled)" if no_sensitivity else ""
        jobs[job_id]["phase"]  = f"Running signature analysis{sens_note}…"
        _persist_job(job_id)

        try:
            configure(locate_mpcmdrun())
        except FileNotFoundError as exc:
            jobs[job_id]["status"] = "error"
            jobs[job_id]["phase"]  = str(exc)
            _persist_job(job_id)
            return

        report = analyse(filepath, no_sensitivity=no_sensitivity, quiet=True)
        sig_dict = asdict(report)

        # Record paths to generated files so endpoints can serve them
        jobs[job_id]["signature_result"]  = sig_dict
        jobs[job_id]["patched_file_path"] = sig_dict.get("patched_file")
        jobs[job_id]["yara_file_path"]    = _yara_path_for(filepath)

        hit_count = len(sig_dict.get("hits", []))
        jobs[job_id]["status"]       = "complete"
        jobs[job_id]["phase"]        = f"Done — {hit_count} signature(s) found"
        jobs[job_id]["completed_at"] = datetime.now().isoformat()

    except Exception as e:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["phase"]  = f"Internal error: {e}"

    _persist_job(job_id)


def _yara_path_for(filepath: str) -> str | None:
    """Return the YARA file path that DefenderCheck would have written, if it exists."""
    base, _ = os.path.splitext(filepath)
    candidate = f"{base}_signatures.yar"
    return candidate if os.path.exists(candidate) else None


def run_analysis(job_id: str, filepath: str, duration: int,
                 mode: str, no_sensitivity: bool):
    with analysis_lock:
        if mode == "signature":
            _run_signature(job_id, filepath, no_sensitivity)
        else:
            _run_sandbox(job_id, filepath, duration)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    if f.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    mode           = request.form.get("mode", "sandbox")
    duration       = int(request.form.get("duration", 30))
    duration       = max(5, min(duration, 300))
    no_sensitivity = request.form.get("no_sensitivity", "false").lower() == "true"

    job_id      = str(uuid.uuid4())
    display_name = secure_filename(f.filename) or "sample"
    extension    = os.path.splitext(display_name)[1]
    filepath     = os.path.join(UPLOAD_DIR, f"{job_id}{extension}")
    f.save(filepath)

    jobs[job_id] = {
        "job_id":            job_id,
        "filename":          display_name,
        "filepath":          filepath,
        "mode":              mode,
        "duration":          duration,
        "no_sensitivity":    no_sensitivity,
        "status":            "queued",
        "phase":             "Queued",
        "submitted_at":      datetime.now().isoformat(),
        "completed_at":      None,
        "scan_result":       None,
        "monitor_result":    None,
        "signature_result":  None,
        "patched_file_path": None,
        "yara_file_path":    None,
    }

    t = threading.Thread(
        target=run_analysis,
        args=(job_id, filepath, duration, mode, no_sensitivity),
        daemon=True,
    )
    t.start()

    return jsonify({"job_id": job_id})


@app.route("/api/status/<job_id>")
def status(job_id: str):
    job = jobs.get(job_id)
    if not job:
        path = os.path.join(RESULTS_DIR, f"{job_id}.json")
        if os.path.exists(path):
            with open(path) as fh:
                job = json.load(fh)
                jobs[job_id] = job
                if _migrate_legacy_job(job):
                    _persist_job(job_id)
        else:
            return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@app.route("/api/jobs")
def list_jobs():
    summary = []
    for jid, j in sorted(
        jobs.items(), key=lambda x: x[1].get("submitted_at", ""), reverse=True
    ):
        scan = j.get("scan_result") or {}
        mon  = j.get("monitor_result") or {}
        sig  = j.get("signature_result") or {}
        assessment = mon.get("assessment") or {}
        summary.append({
            "job_id":       jid,
            "filename":     j.get("filename"),
            "mode":         j.get("mode", "sandbox"),
            "status":       j.get("status"),
            "submitted_at": j.get("submitted_at"),
            "verdict":      scan.get("verdict"),
            "assessment_status": assessment.get("status"),
            "sig_hits":     len(sig.get("hits", [])),
        })
    return jsonify(summary[:50])


@app.route("/api/jobs/<job_id>", methods=["DELETE"])
def delete_job(job_id: str):
    job = jobs.pop(job_id, None)
    if job:
        for path_key in ("filepath", "patched_file_path", "yara_file_path"):
            p = job.get(path_key)
            if p:
                try:
                    os.remove(p)
                except Exception:
                    pass
        try:
            os.remove(os.path.join(RESULTS_DIR, f"{job_id}.json"))
        except Exception:
            pass
        return jsonify({"deleted": job_id})
    return jsonify({"error": "Not found"}), 404


@app.route("/api/jobs/<job_id>/patched")
def download_patched(job_id: str):
    """Download the patched binary produced by signature analysis."""
    job = jobs.get(job_id)
    if not job:
        abort(404)
    path = job.get("patched_file_path")
    if not path or not os.path.exists(path):
        return jsonify({"error": "Patched file not available"}), 404
    base     = os.path.splitext(job.get("filename", "file"))[0]
    ext      = os.path.splitext(job.get("filename", "file"))[1]
    dl_name  = f"{base}_patched{ext}"
    return send_file(path, as_attachment=True, download_name=dl_name)


@app.route("/api/jobs/<job_id>/yara")
def download_yara(job_id: str):
    """Download the YARA rules produced by signature analysis."""
    job = jobs.get(job_id)
    if not job:
        abort(404)
    path = job.get("yara_file_path")
    if not path or not os.path.exists(path):
        return jsonify({"error": "YARA file not available"}), 404
    base    = os.path.splitext(job.get("filename", "file"))[0]
    dl_name = f"{base}_signatures.yar"
    return send_file(path, as_attachment=True, download_name=dl_name)


# ── Startup ───────────────────────────────────────────────────────────────────

def main():
    _load_results_from_disk()
    print("=" * 60)
    print("  LocalScan — Malware Analysis Sandbox")
    print("  http://localhost:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)


if __name__ == "__main__":
    main()
