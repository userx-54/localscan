import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import monitor


FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE = r"C:\MalwareAnalysis\uploads\invented-sample.exe"


def info(pid, name, ppid, create_time, exe=None, cmdline=None):
    return {
        "pid": pid,
        "name": name,
        "exe": exe or name,
        "cmdline": cmdline or [name],
        "ppid": ppid,
        "create_time": create_time,
    }


def state(root=(100, 1.0)):
    return {
        "root": root,
        "tracked": {root},
        "by_pid": {root[0]: root},
        "infos": {root: {"pid": root[0], "name": "invented-sample.exe", "exe": SAMPLE}},
        "sysmon_guids": set(),
        "guid_identity": {},
    }


def result():
    return {"new_processes": [], "new_connections": [], "timeline": []}


def test_process_tree_rejects_unrelated_and_accepts_nested_descendants():
    st = state()
    out = result()
    current = {
        101: info(101, "ordinary.exe", 100, 2.0),
        102: info(102, "nested.exe", 101, 3.0),
        900: info(900, "background.exe", 1, 4.0),
    }
    monitor._accept_process_snapshot(current, st, out, 1.0)
    assert [p["pid"] for p in out["new_processes"]] == [101, 102]
    assert all(p["parent_identity"] for p in out["new_processes"])


def test_root_is_tracked_but_not_emitted_and_pid_reuse_is_rejected():
    st = state()
    out = result()
    monitor._accept_process_snapshot({100: info(100, "invented-sample.exe", None, 1.0)}, st, out, 0)
    monitor._accept_process_snapshot({100: info(100, "reused.exe", None, 9.0)}, st, out, 1)
    assert out["new_processes"] == []
    assert st["by_pid"][100] == (100, 1.0)


def test_indicator_class_is_exact_enum():
    st = state()
    out = result()
    monitor._accept_process_snapshot({101: info(101, "cmd.exe", 100, 2.0)}, st, out, 1)
    assert out["new_processes"][0]["indicator_class"] == "suspicious_process_name"
    st = state()
    out = result()
    monitor._accept_process_snapshot({101: info(101, "ordinary.exe", 100, 2.0)}, st, out, 1)
    assert out["new_processes"][0]["indicator_class"] == "none"


def test_connections_require_live_tracked_process_identity():
    st = state()
    current = {101: info(101, "ordinary.exe", 100, 2.0), 900: info(900, "other.exe", 1, 4.0)}
    out = result()
    monitor._accept_process_snapshot(current, st, out, 1)
    live = {
        ident[0]: ident
        for ident in (monitor._process_identity(pid, item["create_time"]) for pid, item in current.items())
        if ident in st["tracked"]
    }
    assert live[101] == (101, 2.0)
    assert 900 not in live


def test_xml_fixture_namespace_and_supported_fields():
    event = monitor._parse_event_xml((FIXTURES / "defender-1116.xml").read_text())
    assert event["event_id"] == 1116
    assert event["record_id"] == 7301
    assert event["data"]["Threat Name"] == "Test:Benign.Sample"
    events, failures = monitor._parse_event_output((FIXTURES / "sysmon-events.xml").read_text())
    assert not failures
    assert [e["event_id"] for e in events] == [1, 3, 11, 22]


def test_duplicate_provider_record_ids_collapse():
    ev = {"provider": "p", "record_id": 4, "utc_time": None, "event_id": 1, "data": {}}
    accepted, failures = monitor._events_after_watermark([ev, dict(ev)], {"record_id": 1}, None, None)
    assert len(accepted) == 1
    assert not failures


def test_non_monotonic_record_ids_degrade():
    events = [
        {"provider": "p", "record_id": 7},
        {"provider": "p", "record_id": 9},
        {"provider": "p", "record_id": 8},
    ]
    _, failures = monitor._events_after_watermark(events, {"record_id": 1}, None, None)
    assert failures


def test_defender_and_sysmon_reject_unrelated_events():
    st = state()
    unrelated = {
        "provider": "p", "channel": "c", "event_id": 1116, "record_id": 5,
        "utc_time": None, "data": {"Path": r"C:\other\not-sample.exe", "Process Name": "other.exe"},
    }
    assert monitor._correlate_defender_events([unrelated], SAMPLE, st) == []
    sysmon = dict(unrelated, event_id=3, data={"ProcessGuid": "{other}"})
    out = result()
    assert monitor._correlate_sysmon_events([sysmon], SAMPLE, st, out, 1) == []


def test_supported_sysmon_chain_is_correlated():
    events, _ = monitor._parse_event_output((FIXTURES / "sysmon-events.xml").read_text())
    st = state((4242, 1.0))
    st["infos"][st["root"]]["name"] = "invented-sample.exe"
    st["infos"][st["root"]]["exe"] = SAMPLE
    out = result()
    accepted = monitor._correlate_sysmon_events(events, SAMPLE, st, out, 1)
    assert [e["event_id"] for e in accepted] == [1, 3, 11, 22]


def test_unsupported_sysmon_id_is_ignored():
    st = state()
    out = result()
    event = {"event_id": 99, "provider": "p", "record_id": 4, "data": {"ProcessGuid": "{x}"}}
    assert monitor._correlate_sysmon_events([event], SAMPLE, st, out, 1) == []


def test_query_failure_is_not_empty_success(monkeypatch):
    monkeypatch.setattr(monitor.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError("missing")))
    events, ok, detail = monitor._wevtutil_query_xml("x")
    assert events == []
    assert not ok
    assert detail


def test_result_is_json_encodable():
    payload = {"coverage": {"processes": monitor._coverage("available")}, "new_processes": [], "new_connections": [], "defender_alerts": [], "sysmon_alerts": []}
    json.dumps(payload)


DISCLAIMER = (
    "Rule-based observation, not a probability or malware verdict. It covers "
    "only events observed during this run and attributed to the sample process "
    "tree. No observed indicators does not mean the file is safe."
)


def assessment_payload(**updates):
    payload = result()
    payload.update({
        "coverage": {"processes": {"status": "available", "detail": ""}},
        "errors": [],
        "defender_alerts": [],
        "sysmon_alerts": [],
    })
    payload.update(updates)
    return payload


def correlated_event(event_id, record_id=1, kind="process_guid"):
    return {
        "provider": "Sysmon",
        "record_id": record_id,
        "event_id": event_id,
        "correlation": {"kind": kind},
        "data": {},
    }


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"errors": ["launch failed"]}, "inconclusive"),
        ({"coverage": {"processes": {"status": "unavailable", "detail": "missing"}}}, "inconclusive"),
        ({"coverage": {"processes": {"status": "degraded", "detail": "partial"}}}, "inconclusive"),
        ({}, "no_correlated_indicators_observed"),
        ({"new_processes": [{"identity": {"pid": 101, "create_time": 2.0}, "name": "worker.exe", "indicator_class": "none"}]}, "activity_observed"),
        ({"new_connections": [{"identity": {"pid": 101, "create_time": 2.0}, "protocol": "tcp", "laddr": "a", "raddr": "b"}]}, "activity_observed"),
        ({"sysmon_alerts": [correlated_event(22)]}, "activity_observed"),
        ({"new_processes": [{"identity": {"pid": 101, "create_time": 2.0}, "name": "cmd.exe", "indicator_class": "suspicious_process_name"}]}, "suspicious_indicators_observed"),
        ({"defender_alerts": [correlated_event(1116, kind="sample_path")]}, "defender_detection_observed"),
    ],
)
def test_assessment_status_truth_table(updates, expected):
    assessment = monitor.assess_evidence(assessment_payload(**updates))
    assert assessment["status"] == expected


def test_duplicate_suspicious_observations_do_not_escalate():
    process = {
        "identity": {"pid": 101, "create_time": 2.0},
        "name": "cmd.exe",
        "indicator_class": "suspicious_process_name",
    }
    one = monitor.assess_evidence(assessment_payload(new_processes=[process]))
    many = monitor.assess_evidence(assessment_payload(new_processes=[process, dict(process)]))
    assert one["status"] == many["status"] == "suspicious_indicators_observed"


def test_uncorrelated_events_have_no_assessment_effect():
    payload = assessment_payload(
        defender_alerts=[{"event_id": 1116}],
        sysmon_alerts=[{"event_id": 22}],
    )
    assert monitor.assess_evidence(payload)["status"] == "no_correlated_indicators_observed"


def test_lower_tier_evidence_is_retained_without_upgrading_inconclusive():
    payload = assessment_payload(
        coverage={"processes": {"status": "degraded", "detail": "poll failed"}},
        new_processes=[{
            "identity": {"pid": 101, "create_time": 2.0},
            "name": "cmd.exe",
            "indicator_class": "suspicious_process_name",
        }],
    )
    assessment = monitor.assess_evidence(payload)
    assert assessment["status"] == "inconclusive"
    assert any("suspicious" in reason.lower() for reason in assessment["reasons"])


def test_assessment_is_json_encodable_and_does_not_mutate_telemetry():
    payload = assessment_payload(
        new_processes=[{
            "identity": {"pid": 101, "create_time": 2.0},
            "name": "worker.exe",
            "indicator_class": "none",
        }],
    )
    before = json.dumps(payload, sort_keys=True)
    assessment = monitor.assess_evidence(payload)
    assert assessment["disclaimer"] == DISCLAIMER
    json.dumps(assessment)
    assert json.dumps(payload, sort_keys=True) == before
