"""
monitor.py - Dynamic execution monitoring.

Telemetry is retained only when it can be attributed to the submitted sample
or to a process that descends from the sample.  Collection coverage is kept
separate from the evidence lists so that no observations is distinguishable
from no visibility.
"""

import os
import subprocess
import time
import socket
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

import psutil


# ---------------------------------------------------------------------------
# Coverage and process snapshots
# ---------------------------------------------------------------------------


def _coverage(status: str, detail: str = "") -> dict:
    return {"status": status, "detail": detail[:240]}


def _process_identity(pid, create_time):
    try:
        return (int(pid), float(create_time))
    except (TypeError, ValueError):
        return None


def _snapshot_processes_detailed():
    """Return a process snapshot and a safe summary of snapshot failures."""
    procs = {}
    failures = []
    try:
        iterator = psutil.process_iter(
            ["pid", "name", "exe", "cmdline", "ppid", "create_time"]
        )
        for p in iterator:
            try:
                info = dict(p.info)
                identity = _process_identity(info.get("pid", p.pid), info.get("create_time"))
                if identity is None:
                    failures.append("process identity unavailable")
                    continue
                info["pid"] = identity[0]
                info["create_time"] = identity[1]
                procs[identity[0]] = info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                failures.append("process lookup denied or exited")
            except Exception:
                failures.append("process lookup failed")
    except Exception:
        failures.append("process snapshot failed")
    return procs, failures


def snapshot_processes() -> dict:
    """Return ``{pid: info_dict}`` for all live processes."""
    return _snapshot_processes_detailed()[0]


def _format_address(address) -> str:
    if not address:
        return ""
    try:
        return f"{address.ip}:{address.port}"
    except AttributeError:
        try:
            return f"{address[0]}:{address[1]}"
        except (IndexError, TypeError):
            return str(address)


def _connection_protocol(sock_type):
    if sock_type is None:
        return "unknown"
    try:
        return int(sock_type)
    except (TypeError, ValueError):
        return str(sock_type)


def _snapshot_connections_detailed():
    result = []
    failures = []
    try:
        for c in psutil.net_connections(kind="all"):
            try:
                result.append({
                    "laddr": _format_address(c.laddr),
                    "raddr": _format_address(c.raddr),
                    "status": c.status,
                    "pid": c.pid,
                    "protocol": _connection_protocol(getattr(c, "type", None)),
                })
            except Exception:
                failures.append("connection record parse failed")
    except Exception:
        failures.append("connection snapshot failed")
    return result, failures


def snapshot_connections() -> set:
    """Return a set of ``laddr->raddr`` strings for active connections."""
    connections, _ = _snapshot_connections_detailed()
    return {f"{c['laddr']}->{c['raddr']}" for c in connections}


def snapshot_connections_full() -> list:
    """Return full connection information, retaining the owning PID."""
    return _snapshot_connections_detailed()[0]


# ---------------------------------------------------------------------------
# Event log XML helpers (wevtutil -- no external dependency)
# ---------------------------------------------------------------------------


def _local_name(tag):
    return tag.rsplit("}", 1)[-1]


def _first_child(root, name):
    for child in root.iter():
        if _local_name(child.tag) == name:
            return child
    return None


def _parse_event_xml(xml_text: str):
    """Parse the stable Windows Event XML fields and named EventData."""
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, TypeError):
        return None
    if _local_name(root.tag) != "Event":
        return None
    system = _first_child(root, "System")
    if system is None:
        return None
    provider = None
    channel = None
    event_id = None
    record_id = None
    utc_time = None
    for child in system:
        name = _local_name(child.tag)
        if name == "Provider":
            provider = child.attrib.get("Name")
        elif name == "Channel":
            channel = child.text
        elif name == "EventID":
            try:
                event_id = int((child.text or "").strip())
            except ValueError:
                pass
        elif name == "EventRecordID":
            try:
                record_id = int((child.text or "").strip())
            except ValueError:
                pass
        elif name == "TimeCreated":
            utc_time = child.attrib.get("SystemTime")
    if provider is None or channel is None or event_id is None or record_id is None:
        return None
    fields = {}
    event_data = _first_child(root, "EventData")
    if event_data is not None:
        for field in event_data:
            if _local_name(field.tag) != "Data":
                continue
            name = field.attrib.get("Name")
            if name:
                fields[name] = field.text or ""
    event = {
        "provider": provider,
        "channel": (channel or "").strip(),
        "event_id": event_id,
        "record_id": record_id,
        "utc_time": utc_time,
        "data": fields,
    }
    # Keeping named fields at the top level makes the result useful to callers
    # while ``data`` remains the canonical parser representation.
    event.update(fields)
    return event


def _parse_event_output(stdout: str):
    """Parse wevtutil's concatenated ``<Event>`` XML output."""
    if not stdout or not stdout.strip():
        return [], []
    text = stdout.strip()
    chunks = []
    try:
        root = ET.fromstring(text)
        if _local_name(root.tag) == "Events":
            chunks = [ET.tostring(node, encoding="unicode") for node in root]
        else:
            chunks = [ET.tostring(root, encoding="unicode")]
    except ET.ParseError:
        # wevtutil emits adjacent Event documents, which are not one XML
        # document. Wrapping is safe because Event's namespace stays intact.
        try:
            wrapper = ET.fromstring(f"<Events>{text}</Events>")
            chunks = [ET.tostring(node, encoding="unicode") for node in wrapper]
        except ET.ParseError:
            return [], ["event XML parse failed"]
    events = []
    failures = []
    for chunk in chunks:
        parsed = _parse_event_xml(chunk)
        if parsed is None:
            failures.append("event record missing required XML fields")
        else:
            events.append(parsed)
    return events, failures




def _wevtutil_query_xml(logname: str, max_events: int = 30, query: str = ""):
    """Return ``(events, succeeded, detail)`` for an XML event query."""
    try:
        cmd = ["wevtutil", "qe", logname, f"/c:{max_events}", "/rd:true", "/f:xml"]
        if query:
            cmd.append(f"/q:{query}")
        response = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if response.returncode != 0:
            return [], False, "event query failed"
        events, failures = _parse_event_output(response.stdout)
        if failures:
            return events, False, "; ".join(failures)
        return events, True, ""
    except Exception:
        return [], False, "event query unavailable"


def _wevtutil_count(logname: str):
    """Return the record count, or ``None`` when the count is unavailable."""
    try:
        response = subprocess.run(
            ["wevtutil", "gi", logname], capture_output=True, text=True, timeout=5
        )
        if response.returncode != 0:
            return None
        for line in response.stdout.splitlines():
            if "numberOfLogRecords" in line:
                try:
                    return int(line.split(":", 1)[-1].strip())
                except ValueError:
                    return None
    except Exception:
        return None
    return None


def _event_watermark(logname: str):
    events, succeeded, detail = _wevtutil_query_xml(logname, max_events=1)
    if not succeeded:
        return None, detail
    if not events:
        return {"record_id": None, "utc_time": None}, ""
    event = events[0]
    return {"record_id": event["record_id"], "utc_time": event.get("utc_time")}, ""


def _event_epoch(value):
    if not value:
        return None
    try:
        normalized = value.strip().replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).astimezone(timezone.utc).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _events_after_watermark(events, watermark, run_start, now):
    """Filter, deduplicate, and diagnose record-ID anomalies."""
    accepted = []
    seen = set()
    failures = []
    watermark_id = watermark.get("record_id") if watermark else None
    previous = None
    direction = None
    for event in events:
        record_id = event.get("record_id")
        provider = event.get("provider")
        if record_id is None or not provider:
            failures.append("event record identity missing")
            continue
        if previous is not None and direction is None and record_id != previous:
            direction = 1 if record_id > previous else -1
        elif previous is not None and direction == 1 and record_id < previous:
            failures.append("event record ID rollover or non-monotonic input")
        elif previous is not None and direction == -1 and record_id > previous:
            failures.append("event record ID rollover or non-monotonic input")
        if watermark_id is not None and record_id < watermark_id:
            failures.append("event record ID rollover or stale pre-watermark record")
        previous = record_id
        if watermark_id is not None and record_id <= watermark_id:
            continue
        event_time = _event_epoch(event.get("utc_time"))
        if event_time is not None and run_start is not None and event_time < run_start:
            continue
        if event_time is not None and now is not None and event_time > now:
            continue
        key = (provider, record_id)
        if key not in seen:
            seen.add(key)
            accepted.append(event)
    return accepted, failures


def _wevtutil_query(logname: str, max_events: int = 30, query: str = "") -> list:
    """Compatibility wrapper returning parsed XML event dictionaries."""
    return _wevtutil_query_xml(logname, max_events=max_events, query=query)[0]


def get_defender_events(max_events: int = 30) -> list:
    return _wevtutil_query("Microsoft-Windows-Windows Defender/Operational", max_events=max_events)


def get_sysmon_events(max_events: int = 50) -> list:
    return _wevtutil_query("Microsoft-Windows-Sysmon/Operational", max_events=max_events)


def sysmon_available() -> bool:
    try:
        response = subprocess.run(
            ["wevtutil", "gl", "Microsoft-Windows-Sysmon/Operational"],
            capture_output=True, text=True, timeout=5,
        )
        return response.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Process helpers and correlation
# ---------------------------------------------------------------------------


def _tracked_process_entry(info, parent_identity, elapsed):
    name = info.get("name") or ""
    normalized_name = os.path.basename(name).lower()
    identity = _process_identity(info.get("pid"), info.get("create_time"))
    return {
        "pid": identity[0],
        "create_time": identity[1],
        "identity": {"pid": identity[0], "create_time": identity[1]},
        "name": name,
        "exe": info.get("exe") or "",
        "cmdline": " ".join(info.get("cmdline") or [])[:200],
        "ppid": info.get("ppid"),
        "parent_identity": {
            "pid": parent_identity[0], "create_time": parent_identity[1]
        },
        "indicator_class": (
            "suspicious_process_name" if normalized_name in SUSPICIOUS_PROCS else "none"
        ),
        "time": round(elapsed, 2),
    }


def _accept_process_snapshot(current, state, result, elapsed):
    """Add only descendants whose live or tracked parent identity is known."""
    live = {
        identity[0]: identity
        for identity in (_process_identity(pid, info.get("create_time")) for pid, info in current.items())
        if identity is not None
    }
    pending = list(current.values())
    added = 0
    while pending:
        progress = False
        remaining = []
        for info in pending:
            identity = _process_identity(info.get("pid"), info.get("create_time"))
            if identity is None:
                continue
            if identity == state["root"]:
                continue
            old = state["by_pid"].get(identity[0])
            if old is not None and old != identity:
                # PID reuse is never evidence for the old process identity.
                continue
            parent_pid = info.get("ppid")
            parent_identity = live.get(parent_pid)
            if parent_identity is None:
                parent_identity = state["by_pid"].get(parent_pid)
            if parent_identity is None or parent_identity not in state["tracked"]:
                remaining.append(info)
                continue
            if identity in state["tracked"]:
                continue
            state["tracked"].add(identity)
            state["by_pid"][identity[0]] = identity
            state["infos"][identity] = dict(info)
            entry = _tracked_process_entry(info, parent_identity, elapsed)
            result["new_processes"].append(entry)
            result["timeline"].append({
                "time": round(elapsed, 2),
                "type": "new_process",
                "data": f"PID {identity[0]} [{info.get('name', '')}] - {entry['cmdline'][:120]}",
            })
            added += 1
            progress = True
        if not progress:
            break
        pending = remaining
    return added


def _root_process_identity(pid):
    try:
        process = psutil.Process(pid)
        identity = _process_identity(pid, process.create_time())
        if identity is None:
            return None, "root process creation time unavailable"
        return identity, ""
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None, "root process identity unavailable"
    except Exception:
        return None, "root process identity lookup failed"


def _path_matches_sample(value, filepath):
    if not value or not filepath:
        return False
    try:
        observed = os.path.normcase(os.path.abspath(str(value)))
        sample = os.path.normcase(os.path.abspath(str(filepath)))
        return observed == sample
    except (TypeError, ValueError):
        return False


def _event_fields(event):
    fields = event.get("data")
    return fields if isinstance(fields, dict) else event


def _copy_correlated_event(event, correlation):
    copied = {
        "provider": event.get("provider"),
        "channel": event.get("channel"),
        "event_id": event.get("event_id"),
        "record_id": event.get("record_id"),
        "utc_time": event.get("utc_time"),
        "data": dict(_event_fields(event)),
        "correlation": correlation,
    }
    copied.update(copied["data"])
    return copied


def _correlate_defender_events(events, filepath, state):
    accepted = []
    tracked_names = set()
    tracked_exes = set()
    for info in state["infos"].values():
        if info.get("name"):
            tracked_names.add(os.path.basename(info["name"]).lower())
        if info.get("exe"):
            tracked_exes.add(os.path.normcase(os.path.abspath(info["exe"])))
    for event in events:
        if event.get("event_id") != 1116:
            continue
        fields = _event_fields(event)
        path = fields.get("Path")
        process_name = fields.get("Process Name")
        if _path_matches_sample(path, filepath):
            correlation = {"kind": "sample_path", "path": filepath}
        else:
            process_identity = None
            if process_name:
                normalized = os.path.normcase(os.path.abspath(process_name))
                if normalized in tracked_exes or os.path.basename(process_name).lower() in tracked_names:
                    for identity, info in state["infos"].items():
                        if (os.path.basename(info.get("name") or "").lower() == os.path.basename(process_name).lower()
                                or os.path.normcase(os.path.abspath(info.get("exe") or "")) == normalized):
                            process_identity = {"pid": identity[0], "create_time": identity[1]}
                            break
            if process_identity is None:
                continue
            correlation = {"kind": "process_identity", "identity": process_identity}
        accepted.append(_copy_correlated_event(event, correlation))
    return accepted


def _int_field(fields, name):
    try:
        return int(str(fields.get(name, "")), 0)
    except (TypeError, ValueError):
        return None


def _sysmon_root_matches(fields, filepath, state):
    pid = _int_field(fields, "ProcessId")
    if pid != state["root"][0]:
        return False
    image = fields.get("Image") or ""
    if _path_matches_sample(image, filepath):
        return True
    root_info = state.get("infos", {}).get(state["root"], {})
    root_name = os.path.basename(root_info.get("name") or "").lower()
    return bool(root_name and os.path.basename(image).lower() == root_name)


def _sysmon_process_entry(fields, identity, parent_identity, elapsed):
    info = {
        "pid": identity[0],
        "create_time": identity[1],
        "name": os.path.basename(fields.get("Image") or ""),
        "exe": fields.get("Image") or "",
        "cmdline": fields.get("CommandLine") or "",
        "ppid": _int_field(fields, "ParentProcessId"),
    }
    return _tracked_process_entry(info, parent_identity, elapsed)


def _correlate_sysmon_events(events, filepath, state, result, elapsed):
    accepted = []
    # Process creation records may arrive child-first in reverse-order queries.
    remaining = [e for e in events if e.get("event_id") == 1]
    while remaining:
        progress = False
        next_remaining = []
        for event in remaining:
            fields = _event_fields(event)
            guid = fields.get("ProcessGuid")
            parent_guid = fields.get("ParentProcessGuid")
            if not guid:
                continue
            if guid in state["sysmon_guids"]:
                accepted.append(_copy_correlated_event(event, {"kind": "process_guid", "process_guid": guid}))
                continue
            if _sysmon_root_matches(fields, filepath, state):
                state["sysmon_guids"].add(guid)
                state["guid_identity"][guid] = state["root"]
                accepted.append(_copy_correlated_event(event, {"kind": "root_process_guid", "process_guid": guid}))
                progress = True
                continue
            if parent_guid not in state["sysmon_guids"]:
                next_remaining.append(event)
                continue
            parent_identity = state["guid_identity"].get(parent_guid)
            if parent_identity is None:
                next_remaining.append(event)
                continue
            pid = _int_field(fields, "ProcessId")
            identity = state["by_pid"].get(pid) if pid is not None else None
            if identity is None:
                # Sysmon's GUID is the lifetime identity for processes missed by
                # polling; the event timestamp supplies a stable creation value.
                created = _event_epoch(event.get("utc_time")) or time.time()
                identity = (pid, created) if pid is not None else None
            if identity is None:
                next_remaining.append(event)
                continue
            if identity[0] in state["by_pid"] and state["by_pid"][identity[0]] != identity:
                continue
            state["sysmon_guids"].add(guid)
            state["guid_identity"][guid] = identity
            state["tracked"].add(identity)
            state["by_pid"][identity[0]] = identity
            state["infos"].setdefault(identity, {
                "pid": identity[0], "create_time": identity[1],
                "name": os.path.basename(fields.get("Image") or ""),
                "exe": fields.get("Image") or "",
            })
            result["new_processes"].append(_sysmon_process_entry(fields, identity, parent_identity, elapsed))
            result["timeline"].append({
                "time": round(elapsed, 2), "type": "new_process",
                "data": f"PID {identity[0]} [{fields.get('Image', '')}] - correlated Sysmon ProcessGuid",
            })
            accepted.append(_copy_correlated_event(event, {"kind": "process_guid", "process_guid": guid}))
            progress = True
        if not progress:
            break
        remaining = next_remaining

    for event in events:
        if event.get("event_id") not in {3, 11, 22}:
            continue
        fields = _event_fields(event)
        guid = fields.get("ProcessGuid")
        if guid not in state["sysmon_guids"]:
            continue
        accepted.append(_copy_correlated_event(event, {"kind": "process_guid", "process_guid": guid}))
    return accepted


def kill_process_tree(pid: int):
    """Kill a process and all its descendants."""
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child.kill()
            except Exception:
                pass
        try:
            parent.kill()
        except Exception:
            pass
    except psutil.NoSuchProcess:
        pass


# ---------------------------------------------------------------------------
# Evidence assessment
# ---------------------------------------------------------------------------

SUSPICIOUS_PROCS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe", "wmic.exe", "msiexec.exe",
    "schtasks.exe", "reg.exe", "net.exe", "netsh.exe",
    "at.exe", "sc.exe", "bcdedit.exe",
}

ASSESSMENT_DISCLAIMER = (
    "Rule-based observation, not a probability or malware verdict. It covers "
    "only events observed during this run and attributed to the sample process "
    "tree. No observed indicators does not mean the file is safe."
)

_ASSESSMENT_LABELS = {
    "inconclusive": "Inconclusive",
    "no_correlated_indicators_observed": "No correlated indicators observed",
    "activity_observed": "Activity observed",
    "suspicious_indicators_observed": "Suspicious indicators observed",
    "defender_detection_observed": "Defender detection observed",
}

_CORRELATION_KINDS = {
    "sample_path", "process_identity", "process_guid", "root_process_guid",
}


def _is_correlated_event(event):
    if not isinstance(event, dict):
        return False
    correlation = event.get("correlation")
    return (
        isinstance(correlation, dict)
        and correlation.get("kind") in _CORRELATION_KINDS
    )


def _observation_key(observation, kind):
    """Return a stable identity for deduplicating one observation category."""
    identity = observation.get("identity")
    if isinstance(identity, dict) and "pid" in identity:
        return (kind, identity.get("pid"), identity.get("create_time"))
    if kind == "connection":
        return (
            kind, observation.get("protocol"), observation.get("laddr"),
            observation.get("raddr"), observation.get("pid"),
        )
    provider = observation.get("provider")
    record_id = observation.get("record_id")
    if provider is not None or record_id is not None:
        return (kind, provider, record_id)
    return (kind, repr(sorted(observation.items(), key=lambda item: item[0])))


def _unique_observations(observations, kind):
    unique = []
    seen = set()
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        key = _observation_key(observation, kind)
        if key in seen:
            continue
        seen.add(key)
        unique.append(observation)
    return unique


def _activity_reasons(processes, connections, sysmon_events):
    reasons = []
    suspicious = [
        process for process in processes
        if process.get("indicator_class") == "suspicious_process_name"
    ]
    ordinary = [
        process for process in processes
        if process.get("indicator_class") == "none"
    ]
    if suspicious:
        names = sorted({process.get("name") or "unnamed process" for process in suspicious})
        reasons.append("Correlated suspicious process name(s) observed: " + ", ".join(names))
    if ordinary:
        reasons.append(f"Correlated ordinary child process activity observed ({len(ordinary)} process(es))")
    if connections:
        reasons.append(f"Correlated external connection activity observed ({len(connections)} connection(s))")
    event_labels = {3: "network", 11: "file-create", 22: "DNS"}
    for event_id in (3, 11, 22):
        count = sum(event.get("event_id") == event_id for event in sysmon_events)
        if count:
            reasons.append(
                f"Correlated Sysmon {event_labels[event_id]} activity observed ({count} event(s))"
            )
    return reasons, bool(suspicious), bool(ordinary or connections or sysmon_events)


def assess_evidence(result: dict) -> dict:
    """Assess only correlated telemetry using a deterministic precedence."""
    defender = _unique_observations(
        [event for event in result.get("defender_alerts", []) if _is_correlated_event(event)],
        "defender",
    )
    sysmon = _unique_observations(
        [event for event in result.get("sysmon_alerts", []) if _is_correlated_event(event)],
        "sysmon",
    )
    processes = _unique_observations(result.get("new_processes", []), "process")
    connections = _unique_observations(result.get("new_connections", []), "connection")
    activity_reasons, has_suspicious, has_activity = _activity_reasons(
        processes, connections,
        [event for event in sysmon if event.get("event_id") in {3, 11, 22}],
    )

    coverage = result.get("coverage") or {}
    process_coverage = coverage.get("processes") or {}
    process_status = process_coverage.get("status")
    errors = result.get("errors") or []
    execution_failed = bool(errors) or result.get("execution_failed") is True

    if defender:
        status = "defender_detection_observed"
    elif execution_failed or process_status in {"degraded", "unavailable"}:
        status = "inconclusive"
    elif process_status == "available" and has_suspicious:
        status = "suspicious_indicators_observed"
    elif process_status == "available" and has_activity:
        status = "activity_observed"
    elif process_status == "available":
        status = "no_correlated_indicators_observed"
    else:
        status = "inconclusive"

    reasons = []
    if defender:
        reasons.append(f"Sample-correlated Windows Defender detection observed ({len(defender)} event(s))")
    reasons.extend(activity_reasons)
    if execution_failed:
        detail = str(errors[0]) if errors else "execution failed"
        reasons.append(f"Execution failed: {detail}")
    if process_status != "available":
        detail = process_coverage.get("detail") or "process coverage is unavailable"
        reasons.append(f"Process coverage {process_status or 'unavailable'}: {detail}")
    if not reasons:
        reasons.append("No correlated indicators observed during execution.")

    return {
        "status": status,
        "label": _ASSESSMENT_LABELS[status],
        "reasons": reasons,
        "disclaimer": ASSESSMENT_DISCLAIMER,
    }


# ---------------------------------------------------------------------------
# Main monitor entry point
# ---------------------------------------------------------------------------


def execute_and_monitor(filepath: str, duration: int) -> dict:
    """Execute the sample and monitor only sample-correlated observations."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "filepath": filepath,
        "duration_requested": duration,
        "actual_duration": 0.0,
        "sample_pid": None,
        "exit_code": None,
        "terminated_by_us": False,
        "timeline": [],
        "new_processes": [],
        "new_connections": [],
        "defender_alerts": [],
        "sysmon_alerts": [],
        "sysmon_available": False,
        "coverage": {
            "processes": _coverage("unavailable", "not initialized"),
            "connections": _coverage("unavailable", "not initialized"),
            "defender_events": _coverage("unavailable", "not initialized"),
            "sysmon_events": _coverage("unavailable", "not initialized"),
        },
        "errors": [],
        "assessment": None,
    }
    pre_procs, proc_failures = _snapshot_processes_detailed()
    _, conn_failures = _snapshot_connections_detailed()
    result["coverage"]["processes"] = _coverage("degraded" if proc_failures else "available", "; ".join(proc_failures))
    result["coverage"]["connections"] = _coverage("degraded" if conn_failures else "available", "; ".join(conn_failures))

    defender_watermark, defender_detail = _event_watermark("Microsoft-Windows-Windows Defender/Operational")
    if defender_watermark is None:
        result["coverage"]["defender_events"] = _coverage("unavailable", defender_detail)
    else:
        result["coverage"]["defender_events"] = _coverage("available")
    has_sysmon = sysmon_available()
    result["sysmon_available"] = has_sysmon
    sysmon_watermark = None
    if has_sysmon:
        sysmon_watermark, sysmon_detail = _event_watermark("Microsoft-Windows-Sysmon/Operational")
        result["coverage"]["sysmon_events"] = _coverage("available" if sysmon_watermark is not None else "unavailable", sysmon_detail)
    else:
        result["coverage"]["sysmon_events"] = _coverage("unavailable", "Sysmon log unavailable")

    try:
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        proc = subprocess.Popen([filepath], cwd=os.path.dirname(filepath) or ".", creationflags=flags)
        result["sample_pid"] = proc.pid
    except Exception as exc:
        result["errors"].append(f"Execution failed: {exc}")
        result["coverage"]["processes"] = _coverage("unavailable", "sample process did not launch")
        result["assessment"] = assess_evidence(result)
        return result

    start_time = time.time()
    root_identity, root_detail = _root_process_identity(proc.pid)
    if root_identity is None:
        result["coverage"]["processes"] = _coverage("unavailable", root_detail)
        result["errors"].append(root_detail)
        try:
            kill_process_tree(proc.pid)
        except Exception:
            pass
        result["actual_duration"] = round(time.time() - start_time, 2)
        result["assessment"] = assess_evidence(result)
        return result

    state = {
        "root": root_identity,
        "tracked": {root_identity},
        "by_pid": {root_identity[0]: root_identity},
        "infos": {root_identity: {"pid": proc.pid}},
        "sysmon_guids": set(),
        "guid_identity": {},
    }
    result["timeline"].append({"time": 0.0, "type": "execution_start", "data": f"Process started - PID {proc.pid}"})
    seen_connections = set()
    seen_events = {"defender": set(), "sysmon": set()}
    previous_record = {
        "defender": defender_watermark.get("record_id") if defender_watermark else None,
        "sysmon": sysmon_watermark.get("record_id") if sysmon_watermark else None,
    }
    last_event_check = 0.0

    def poll_events(kind, logname, watermark, now):
        if watermark is None:
            return
        query = ""
        if watermark.get("record_id") is not None:
            query = f"*[System[(EventRecordID > {watermark['record_id']})]]"
        events, succeeded, detail = _wevtutil_query_xml(logname, max_events=100, query=query)
        coverage = result["coverage"][f"{kind}_events"]
        if not succeeded:
            coverage["status"] = "degraded" if coverage["status"] == "available" else "unavailable"
            coverage["detail"] = detail[:240]
            return
        filtered, failures = _events_after_watermark(
            events, watermark, start_time, now
        )
        if failures:
            coverage["status"] = "degraded"
            coverage["detail"] = "; ".join(failures)[:240]
        accepted = []
        for event in filtered:
            key = (event.get("provider"), event.get("record_id"))
            if key in seen_events[kind]:
                continue
            seen_events[kind].add(key)
            accepted.append(event)
            previous_record[kind] = max(previous_record[kind] or key[1], key[1])
        if kind == "defender":
            correlated = _correlate_defender_events(accepted, filepath, state)
            result["defender_alerts"].extend(correlated)
            for event in correlated:
                result["timeline"].append({"time": round(now - start_time, 2), "type": "defender_alert", "data": str(event)[:300]})
        else:
            correlated = _correlate_sysmon_events(accepted, filepath, state, result, now - start_time)
            result["sysmon_alerts"].extend(correlated)
            for event in correlated:
                result["timeline"].append({"time": round(now - start_time, 2), "type": "sysmon_alert", "data": str(event)[:300]})

    try:
        while time.time() - start_time < duration:
            now = time.time()
            elapsed = now - start_time
            if proc.poll() is not None:
                result["exit_code"] = proc.returncode
                result["timeline"].append({"time": round(elapsed, 2), "type": "process_exit", "data": f"Sample exited with code {proc.returncode}"})
                break
            current, failures = _snapshot_processes_detailed()
            if failures:
                result["coverage"]["processes"]["status"] = "degraded"
                result["coverage"]["processes"]["detail"] = "; ".join(failures)[:240]
            _accept_process_snapshot(current, state, result, elapsed)
            current_connections, conn_errors = _snapshot_connections_detailed()
            if conn_errors:
                result["coverage"]["connections"]["status"] = "degraded"
                result["coverage"]["connections"]["detail"] = "; ".join(conn_errors)[:240]
            live = {
                identity[0]: identity
                for identity in (_process_identity(pid, info.get("create_time")) for pid, info in current.items())
                if identity is not None and identity in state["tracked"]
            }
            for connection in current_connections:
                pid = connection.get("pid")
                identity = live.get(pid)
                if not connection.get("raddr") or identity is None:
                    continue
                key = (identity, connection.get("protocol"), connection.get("laddr"), connection.get("raddr"))
                if key in seen_connections:
                    continue
                seen_connections.add(key)
                entry = dict(connection)
                entry["identity"] = {"pid": identity[0], "create_time": identity[1]}
                entry["time"] = round(elapsed, 2)
                result["new_connections"].append(entry)
                result["timeline"].append({"time": round(elapsed, 2), "type": "network", "data": f"{entry['laddr']} -> {entry['raddr']} [{entry['status']}] PID {pid}"})
            if elapsed - last_event_check >= 2.0:
                last_event_check = elapsed
                poll_events("defender", "Microsoft-Windows-Windows Defender/Operational", defender_watermark, now)
                if has_sysmon:
                    poll_events("sysmon", "Microsoft-Windows-Sysmon/Operational", sysmon_watermark, now)
            time.sleep(0.5)
    except Exception as exc:
        result["errors"].append(f"Monitor loop error: {exc}")
    finally:
        if proc.poll() is None:
            kill_process_tree(result["sample_pid"])
            result["terminated_by_us"] = True
            result["timeline"].append({"time": round(time.time() - start_time, 1), "type": "terminated", "data": f"Sample killed after {round(time.time() - start_time, 1)}s"})
        result["actual_duration"] = round(time.time() - start_time, 2)

    now = time.time()
    poll_events("defender", "Microsoft-Windows-Windows Defender/Operational", defender_watermark, now)
    result["assessment"] = assess_evidence(result)
    return result
