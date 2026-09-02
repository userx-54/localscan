"""Focused tests for the web entrypoint and job submission boundary."""

import io
import json
import os
from unittest.mock import patch

import pytest

import app as webapp


@pytest.fixture
def client(tmp_path, monkeypatch):
    upload_dir = tmp_path / "uploads"
    results_dir = tmp_path / "results"
    upload_dir.mkdir()
    results_dir.mkdir()

    monkeypatch.setattr(webapp, "UPLOAD_DIR", str(upload_dir))
    monkeypatch.setattr(webapp, "RESULTS_DIR", str(results_dir))
    webapp.jobs.clear()
    webapp.app.config["TESTING"] = True

    yield webapp.app.test_client()

    webapp.jobs.clear()


def test_upload_uses_generated_storage_name(client):
    with patch.object(webapp.threading, "Thread") as thread:
        response = client.post(
            "/api/analyze",
            data={"file": (io.BytesIO(b"sample"), "../../payload.exe")},
            content_type="multipart/form-data",
        )

    assert response.status_code == 200
    job_id = response.get_json()["job_id"]
    job = webapp.jobs[job_id]
    stored_path = job["filepath"]

    assert job["filename"] == "payload.exe"
    assert os.path.basename(stored_path) == f"{job_id}.exe"
    assert os.path.dirname(stored_path) == webapp.UPLOAD_DIR
    assert open(stored_path, "rb").read() == b"sample"
    thread.return_value.start.assert_called_once_with()


def test_run_analysis_holds_global_lock():
    def assert_locked(*_args):
        acquired = webapp.analysis_lock.acquire(blocking=False)
        if acquired:
            webapp.analysis_lock.release()
        assert not acquired

    with patch.object(webapp, "_run_sandbox", side_effect=assert_locked) as sandbox:
        webapp.run_analysis("job", "sample.exe", 30, "sandbox", False)

    sandbox.assert_called_once_with("job", "sample.exe", 30)


def test_main_binds_to_localhost():
    with patch.object(webapp, "_load_results_from_disk") as load_results:
        with patch.object(webapp.app, "run") as run:
            webapp.main()

    load_results.assert_called_once_with()
    run.assert_called_once_with(
        host="127.0.0.1", port=5000, debug=False, threaded=True
    )


def test_history_summary_uses_assessment_status_only(client):
    webapp.jobs["job"] = {
        "job_id": "job",
        "filename": "sample.exe",
        "mode": "sandbox",
        "status": "complete",
        "submitted_at": "2026-01-01T00:00:00",
        "scan_result": {"verdict": "clean"},
        "monitor_result": {
            "assessment": {
                "status": "activity_observed",
                "label": "Activity observed",
                "reasons": ["Correlated child activity observed"],
                "disclaimer": "Rule-based observation, not a probability or malware verdict.",
            }
        },
    }
    payload = client.get("/api/jobs").get_json()
    assert payload[0]["assessment_status"] == "activity_observed"
    assert "risk_score" not in payload[0]
    assert "risk_level" not in payload[0]


def test_load_results_migrates_legacy_monitor_result(client, tmp_path):
    legacy = {
        "job_id": "legacy",
        "filename": "old.exe",
        "mode": "sandbox",
        "status": "complete",
        "monitor_result": {
            "risk_score": {
                "score": 42,
                "level": "medium",
                "reasons": ["Spawned a process"],
            },
            "new_processes": [],
        },
    }
    path = tmp_path / "results" / "legacy.json"
    path.write_text(json.dumps(legacy))
    webapp._load_results_from_disk()

    migrated = webapp.jobs["legacy"]["monitor_result"]
    assert "risk_score" not in migrated
    assert "risk_level" not in migrated
    assert migrated["assessment"]["status"] == "inconclusive"
    assert migrated["assessment"]["reasons"] == [
        "Legacy result used uncorrelated telemetry and cannot be reassessed"
    ]
    persisted = json.loads(path.read_text())
    assert "risk_score" not in json.dumps(persisted)
    assert "risk_level" not in json.dumps(persisted)
    response = client.get("/api/status/legacy")
    assert "risk_score" not in response.get_data(as_text=True)
