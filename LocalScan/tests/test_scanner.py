"""
test_scanner.py — tests for defender_check.scanner

Covers:
  - configure: stores path, overwrites previous value
  - locate_mpcmdrun: registry path, default fallback, FileNotFoundError
  - get_defender_info: winreg unavailable, success, OSError
  - scan: file-not-found, clean, threat, error exit code, timeout/retry,
          get_sig extraction, correct subprocess command
"""

import subprocess
import types
from unittest.mock import MagicMock, call, patch

import pytest

import defender_check.scanner as scanner_mod
from defender_check.models import ScanResult


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_proc(returncode: int, stdout: str = "") -> MagicMock:
    """Return a mock CompletedProcess-like object."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout     = stdout
    return proc


# ── configure ─────────────────────────────────────────────────────────────────

class TestConfigure:
    def test_stores_path(self):
        scanner_mod.configure("/some/path/MpCmdRun.exe")
        assert scanner_mod._mpcmdrun == "/some/path/MpCmdRun.exe"

    def test_overwrites_previous_value(self):
        scanner_mod.configure("/first")
        scanner_mod.configure("/second")
        assert scanner_mod._mpcmdrun == "/second"

    def test_accepts_empty_string(self):
        scanner_mod.configure("")
        assert scanner_mod._mpcmdrun == ""


# ── locate_mpcmdrun ───────────────────────────────────────────────────────────

class TestLocateMpcmdrun:
    def test_returns_default_path_when_it_exists(self, tmp_path):
        fake_exe = tmp_path / "MpCmdRun.exe"
        fake_exe.write_text("")

        with patch("defender_check.scanner._HAS_WINREG", False):
            with patch("defender_check.scanner._DEFAULT_MPCMDRUN", str(fake_exe)):
                result = scanner_mod.locate_mpcmdrun()

        assert result == str(fake_exe)

    def test_raises_when_neither_path_exists(self, tmp_path):
        with patch("defender_check.scanner._HAS_WINREG", False):
            with patch("defender_check.scanner._DEFAULT_MPCMDRUN",
                       str(tmp_path / "nonexistent.exe")):
                with pytest.raises(FileNotFoundError):
                    scanner_mod.locate_mpcmdrun()

    def test_error_message_includes_attempted_path(self, tmp_path):
        sentinel = str(tmp_path / "no_such.exe")
        with patch("defender_check.scanner._HAS_WINREG", False):
            with patch("defender_check.scanner._DEFAULT_MPCMDRUN", sentinel):
                import re
                with pytest.raises(FileNotFoundError, match=re.escape(sentinel)):
                    scanner_mod.locate_mpcmdrun()

    def test_registry_path_preferred_over_default(self, tmp_path, mock_winreg):
        reg_dir = tmp_path / "registry_install"
        reg_dir.mkdir()
        reg_exe = reg_dir / "MpCmdRun.exe"
        reg_exe.write_text("")

        default_exe = tmp_path / "default_MpCmdRun.exe"
        default_exe.write_text("")

        mock_winreg.QueryValueEx.return_value = (str(reg_dir), None)

        with patch("defender_check.scanner._HAS_WINREG", True):
            with patch.object(scanner_mod, "winreg", mock_winreg, create=True):
                with patch("defender_check.scanner._DEFAULT_MPCMDRUN", str(default_exe)):
                    result = scanner_mod.locate_mpcmdrun()

        assert result == str(reg_exe)

    def test_falls_back_to_default_when_registry_raises(self, tmp_path, mock_winreg):
        default_exe = tmp_path / "MpCmdRun.exe"
        default_exe.write_text("")
        mock_winreg.OpenKey.side_effect = OSError("key not found")

        with patch("defender_check.scanner._HAS_WINREG", True):
            with patch.object(scanner_mod, "winreg", mock_winreg, create=True):
                with patch("defender_check.scanner._DEFAULT_MPCMDRUN", str(default_exe)):
                    result = scanner_mod.locate_mpcmdrun()

        assert result == str(default_exe)

    def test_falls_back_when_registry_exe_missing(self, tmp_path, mock_winreg):
        """Registry key exists but the exe at that path does not."""
        default_exe = tmp_path / "MpCmdRun.exe"
        default_exe.write_text("")
        # Registry points to a directory with no MpCmdRun.exe inside
        mock_winreg.QueryValueEx.return_value = (str(tmp_path / "missing_dir"), None)

        with patch("defender_check.scanner._HAS_WINREG", True):
            with patch.object(scanner_mod, "winreg", mock_winreg, create=True):
                with patch("defender_check.scanner._DEFAULT_MPCMDRUN", str(default_exe)):
                    result = scanner_mod.locate_mpcmdrun()

        assert result == str(default_exe)


# ── get_defender_info ─────────────────────────────────────────────────────────

class TestGetDefenderInfo:
    def test_returns_unknown_without_winreg(self):
        with patch("defender_check.scanner._HAS_WINREG", False):
            engine, sigs = scanner_mod.get_defender_info()
        assert engine == "unknown"
        assert sigs   == "unknown"

    def test_reads_versions_from_registry(self, mock_winreg):
        mock_winreg.QueryValueEx.side_effect = [
            ("4.18.23080.2006", None),   # EngineVersion
            ("1.399.100.0",     None),   # SignatureVersion
        ]

        with patch("defender_check.scanner._HAS_WINREG", True):
            with patch.object(scanner_mod, "winreg", mock_winreg, create=True):
                engine, sigs = scanner_mod.get_defender_info()

        assert engine == "4.18.23080.2006"
        assert sigs   == "1.399.100.0"

    def test_returns_unknown_on_oserror(self, mock_winreg):
        mock_winreg.OpenKey.side_effect = OSError("access denied")

        with patch("defender_check.scanner._HAS_WINREG", True):
            with patch.object(scanner_mod, "winreg", mock_winreg, create=True):
                engine, sigs = scanner_mod.get_defender_info()

        assert engine == "unknown"
        assert sigs   == "unknown"

    def test_returns_tuple_of_two_strings(self, mock_winreg):
        with patch("defender_check.scanner._HAS_WINREG", False):
            result = scanner_mod.get_defender_info()
        assert isinstance(result, tuple) and len(result) == 2
        assert all(isinstance(v, str) for v in result)


# ── scan ─────────────────────────────────────────────────────────────────────

class TestScan:
    def setup_method(self):
        scanner_mod.configure("/fake/MpCmdRun.exe")

    # ── File existence ────────────────────────────────────────────────────────

    def test_missing_file_returns_not_found(self, tmp_path):
        result, sig = scanner_mod.scan(str(tmp_path / "missing.exe"))
        assert result == ScanResult.NOT_FOUND
        assert sig is None

    # ── Exit code mapping ─────────────────────────────────────────────────────

    def test_exit_code_0_returns_no_threat(self, tmp_exe):
        with patch("defender_check.scanner.subprocess.run",
                   return_value=_make_proc(0)):
            result, sig = scanner_mod.scan(str(tmp_exe))
        assert result == ScanResult.NO_THREAT
        assert sig is None

    def test_exit_code_2_returns_threat(self, tmp_exe):
        with patch("defender_check.scanner.subprocess.run",
                   return_value=_make_proc(2)):
            result, sig = scanner_mod.scan(str(tmp_exe))
        assert result == ScanResult.THREAT
        assert sig is None

    def test_other_exit_code_returns_error(self, tmp_exe):
        with patch("defender_check.scanner.subprocess.run",
                   return_value=_make_proc(99)):
            result, sig = scanner_mod.scan(str(tmp_exe))
        assert result == ScanResult.ERROR

    # ── Timeout handling ──────────────────────────────────────────────────────

    def test_all_retries_timeout_returns_timeout(self, tmp_exe):
        with patch("defender_check.scanner.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="x", timeout=30)):
            result, sig = scanner_mod.scan(str(tmp_exe))
        assert result == ScanResult.TIMEOUT
        assert sig is None

    def test_timeout_then_success_returns_scan_result(self, tmp_exe):
        """One timeout followed by a successful call should succeed."""
        side_effects = [
            subprocess.TimeoutExpired(cmd="x", timeout=30),
            _make_proc(0),
        ]
        with patch("defender_check.scanner.subprocess.run", side_effect=side_effects):
            result, _ = scanner_mod.scan(str(tmp_exe))
        assert result == ScanResult.NO_THREAT

    def test_retry_count(self, tmp_exe):
        """subprocess.run should be called at most _MAX_RETRIES times on persistent timeout."""
        with patch("defender_check.scanner.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="x", timeout=30)) as mock_run:
            scanner_mod.scan(str(tmp_exe))
        assert mock_run.call_count == scanner_mod._MAX_RETRIES

    # ── Signature extraction ──────────────────────────────────────────────────

    def test_get_sig_extracts_name_from_stdout(self, tmp_exe):
        stdout = "Threat : Trojan:Win32/MimikatzE\nsome other output"
        with patch("defender_check.scanner.subprocess.run",
                   return_value=_make_proc(2, stdout)):
            result, sig = scanner_mod.scan(str(tmp_exe), get_sig=True)
        assert result == ScanResult.THREAT
        assert sig == "Trojan:Win32/MimikatzE"

    def test_get_sig_case_insensitive_match(self, tmp_exe):
        stdout = "THREAT : Trojan:Win32/Test"
        with patch("defender_check.scanner.subprocess.run",
                   return_value=_make_proc(2, stdout)):
            _, sig = scanner_mod.scan(str(tmp_exe), get_sig=True)
        assert sig == "Trojan:Win32/Test"

    def test_get_sig_false_ignores_stdout(self, tmp_exe):
        stdout = "Threat : Trojan:Win32/MimikatzE"
        with patch("defender_check.scanner.subprocess.run",
                   return_value=_make_proc(2, stdout)):
            _, sig = scanner_mod.scan(str(tmp_exe), get_sig=False)
        assert sig is None

    def test_get_sig_no_match_returns_none(self, tmp_exe):
        stdout = "Scan completed. No threat information in output."
        with patch("defender_check.scanner.subprocess.run",
                   return_value=_make_proc(2, stdout)):
            _, sig = scanner_mod.scan(str(tmp_exe), get_sig=True)
        assert sig is None

    def test_get_sig_with_spaces_around_colon(self, tmp_exe):
        stdout = "Threat   :   Trojan:Win32/Spaced"
        with patch("defender_check.scanner.subprocess.run",
                   return_value=_make_proc(2, stdout)):
            _, sig = scanner_mod.scan(str(tmp_exe), get_sig=True)
        assert sig == "Trojan:Win32/Spaced"

    # ── Subprocess command ────────────────────────────────────────────────────

    def test_builds_correct_command(self, tmp_exe):
        scanner_mod.configure("/custom/MpCmdRun.exe")
        with patch("defender_check.scanner.subprocess.run",
                   return_value=_make_proc(0)) as mock_run:
            scanner_mod.scan(str(tmp_exe))

        cmd = mock_run.call_args[0][0]
        assert cmd[0]  == "/custom/MpCmdRun.exe"
        assert "-Scan"             in cmd
        assert "-ScanType"         in cmd
        assert "3"                 in cmd
        assert "-File"             in cmd
        assert str(tmp_exe)        in cmd
        assert "-DisableRemediation" in cmd

    def test_capture_output_enabled(self, tmp_exe):
        with patch("defender_check.scanner.subprocess.run",
                   return_value=_make_proc(0)) as mock_run:
            scanner_mod.scan(str(tmp_exe))
        kwargs = mock_run.call_args[1]
        assert kwargs.get("capture_output") is True

    def test_timeout_passed_to_subprocess(self, tmp_exe):
        with patch("defender_check.scanner.subprocess.run",
                   return_value=_make_proc(0)) as mock_run:
            scanner_mod.scan(str(tmp_exe))
        kwargs = mock_run.call_args[1]
        assert kwargs.get("timeout") == scanner_mod._SCAN_TIMEOUT
