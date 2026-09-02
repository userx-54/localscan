"""Contract tests for the rich web-facing Defender scan result."""

import hashlib
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from defender_check import scanner as scanner_mod


EXPECTED_KEYS = {
    "timestamp",
    "filepath",
    "filename",
    "filesize",
    "magic",
    "hashes",
    "verdict",
    "threats",
    "raw_output",
    "return_code",
    "error",
}


@pytest.fixture
def sample_file(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ\x90\x00payload")
    return path


def run_result(sample_file, returncode=0, stdout="", stderr=""):
    process = SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
    with patch.object(scanner_mod, "find_mpcmdrun", return_value="MpCmdRun.exe"):
        with patch.object(scanner_mod.subprocess, "run", return_value=process) as run:
            result = scanner_mod.scan_with_defender(str(sample_file))
    return result, run


def test_hashes_magic_and_keys(sample_file):
    result, run = run_result(sample_file)
    data = sample_file.read_bytes()

    assert set(result) == EXPECTED_KEYS
    assert result["filesize"] == len(data)
    assert result["magic"] == data[:8].hex().upper()
    assert result["hashes"] == {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    run.assert_called_once_with(
        ["MpCmdRun.exe", "-Scan", "-ScanType", "3", "-File", str(sample_file), "-DisableRemediation"],
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_missing_defender_returns_existing_error_dictionary(sample_file):
    with patch.object(scanner_mod, "find_mpcmdrun", return_value=None):
        result = scanner_mod.scan_with_defender(str(sample_file))

    assert result["verdict"] == "error"
    assert result["error"] == "MpCmdRun.exe not found — is Windows Defender installed?"
    assert result["return_code"] is None


def test_clean_return_code(sample_file):
    result, _ = run_result(sample_file, returncode=0, stdout="clean", stderr="warning")

    assert result["verdict"] == "clean"
    assert result["raw_output"] == "cleanwarning"
    assert result["threats"] == []


def test_threat_return_code_parses_explicit_name(sample_file):
    result, _ = run_result(
        sample_file,
        returncode=2,
        stdout="Threat name: Trojan:Win32/Example.A\n",
        stderr="Defender output",
    )

    assert result["verdict"] == "threat_detected"
    assert result["return_code"] == 2
    assert result["threats"] == ["Trojan:Win32/Example.A"]
    assert result["raw_output"] == "Threat name: Trojan:Win32/Example.A\nDefender output"


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("Detected malware in payload", ["Detected malware in payload"]),
        ("No descriptive details", ["Unknown threat (Defender return code 2)"]),
    ],
)
def test_threat_keyword_and_unknown_fallbacks(sample_file, output, expected):
    result, _ = run_result(sample_file, returncode=2, stdout=output)

    assert result["verdict"] == "threat_detected"
    assert result["threats"] == expected


def test_unrecognized_return_code_is_scan_error(sample_file):
    result, _ = run_result(sample_file, returncode=7, stderr="engine failure")

    assert result["verdict"] == "scan_error"
    assert result["error"] == "MpCmdRun exited with code 7"
    assert result["raw_output"] == "engine failure"


def test_timeout_is_scan_timeout(sample_file):
    with patch.object(scanner_mod, "find_mpcmdrun", return_value="MpCmdRun.exe"):
        with patch.object(
            scanner_mod.subprocess,
            "run",
            side_effect=scanner_mod.subprocess.TimeoutExpired("MpCmdRun.exe", 120),
        ):
            result = scanner_mod.scan_with_defender(str(sample_file))

    assert result["verdict"] == "scan_timeout"
    assert result["error"] == "Scan timed out after 120 seconds"
    assert result["raw_output"] == ""
