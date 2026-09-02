"""
test_cli.py — tests for defender_check.cli

Covers:
  - _parse_args: positional arg, all flags, missing arg exit
  - _print_summary: hit count, patched file display, clean/flagged icons
  - main: file-not-found exit, MpCmdRun-not-found exit, normal flow,
          --json output validity, --json suppresses human-readable lines
"""

import json
import sys
from dataclasses import asdict
from unittest.mock import MagicMock, patch

import pytest

from defender_check.cli import _parse_args, _print_summary, main
from defender_check.models import Hit, Report


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_report(hits=0, patched=None, clean=False) -> Report:
    r = Report(
        target_file="payload.exe",
        file_size=100,
        engine_version="1.0",
        signature_version="2.0",
        patched_file=patched,
        clean_after_patching=clean,
    )
    for i in range(hits):
        r.hits.append(Hit(
            index=i, offset=50 * (i + 1), offset_hex=f"0x{50*(i+1):X}",
            signature=f"Sig{i}", pe_section=None, entropy=5.0,
            entropy_note="medium", strings=[], load_bearing_offsets=[],
            flagged_bytes_hex="AA", yara_rule=f"rule Hit{i} {{}}",
        ))
    return r


# ── _parse_args ───────────────────────────────────────────────────────────────

class TestParseArgs:
    def test_positional_file_stored(self):
        with patch("sys.argv", ["dc", "payload.exe"]):
            args = _parse_args()
        assert args.file == "payload.exe"

    def test_debug_default_is_false(self):
        with patch("sys.argv", ["dc", "payload.exe"]):
            assert _parse_args().debug is False

    def test_no_sensitivity_default_is_false(self):
        with patch("sys.argv", ["dc", "payload.exe"]):
            assert _parse_args().no_sensitivity is False

    def test_json_default_is_false(self):
        with patch("sys.argv", ["dc", "payload.exe"]):
            assert _parse_args().json is False

    def test_debug_flag_sets_true(self):
        with patch("sys.argv", ["dc", "payload.exe", "--debug"]):
            assert _parse_args().debug is True

    def test_no_sensitivity_flag_sets_true(self):
        with patch("sys.argv", ["dc", "payload.exe", "--no-sensitivity"]):
            assert _parse_args().no_sensitivity is True

    def test_json_flag_sets_true(self):
        with patch("sys.argv", ["dc", "payload.exe", "--json"]):
            assert _parse_args().json is True

    def test_all_flags_together(self):
        with patch("sys.argv",
                   ["dc", "x.exe", "--debug", "--no-sensitivity", "--json"]):
            args = _parse_args()
        assert args.debug and args.no_sensitivity and args.json

    def test_missing_positional_arg_exits(self):
        with patch("sys.argv", ["dc"]):
            with pytest.raises(SystemExit):
                _parse_args()

    def test_file_with_path(self):
        with patch("sys.argv", ["dc", "/some/path/binary.exe"]):
            assert _parse_args().file == "/some/path/binary.exe"


# ── _print_summary ────────────────────────────────────────────────────────────

class TestPrintSummary:
    def test_shows_zero_hit_count(self, capsys):
        _print_summary(_make_report(hits=0))
        assert "0" in capsys.readouterr().out

    def test_shows_nonzero_hit_count(self, capsys):
        _print_summary(_make_report(hits=3))
        assert "3" in capsys.readouterr().out

    def test_no_patched_file_no_patched_line(self, capsys):
        _print_summary(_make_report(patched=None))
        out = capsys.readouterr().out
        # The patched-file line must not appear
        assert "patched" not in out.lower()

    def test_shows_patched_file_path(self, capsys):
        _print_summary(_make_report(patched="/out/payload_patched.exe"))
        assert "/out/payload_patched.exe" in capsys.readouterr().out

    def test_shows_clean_indicator_when_clean(self, capsys):
        _print_summary(_make_report(patched="/out/p.exe", clean=True))
        out = capsys.readouterr().out
        assert "clean" in out.lower() or "✓" in out

    def test_shows_flagged_indicator_when_not_clean(self, capsys):
        _print_summary(_make_report(patched="/out/p.exe", clean=False))
        out = capsys.readouterr().out
        assert "flagged" in out.lower() or "✗" in out

    def test_outputs_separator_lines(self, capsys):
        _print_summary(_make_report())
        out = capsys.readouterr().out
        # Should have at least one separator bar
        assert "═" in out or "=" in out or "─" in out


# ── main ─────────────────────────────────────────────────────────────────────

class TestMain:
    def test_exits_1_when_file_not_found(self, tmp_path):
        with patch("sys.argv", ["dc", str(tmp_path / "nope.exe")]):
            with pytest.raises(SystemExit) as exc:
                main()
        assert exc.value.code == 1

    def test_exits_1_when_mpcmdrun_not_found(self, tmp_path):
        payload = tmp_path / "payload.exe"
        payload.write_bytes(b"\x00" * 10)

        with patch("sys.argv", ["dc", str(payload)]):
            with patch("defender_check.cli.locate_mpcmdrun",
                       side_effect=FileNotFoundError("not found")):
                with pytest.raises(SystemExit) as exc:
                    main()
        assert exc.value.code == 1

    def test_normal_run_calls_analyse(self, tmp_path):
        payload = tmp_path / "payload.exe"
        payload.write_bytes(b"\x00" * 10)
        mock_report = _make_report()

        with patch("sys.argv", ["dc", str(payload)]):
            with patch("defender_check.cli.locate_mpcmdrun",
                       return_value="/fake/MpCmdRun.exe"):
                with patch("defender_check.cli.configure"):
                    with patch("defender_check.cli.analyse",
                               return_value=mock_report) as mock_analyse:
                        main()

        mock_analyse.assert_called_once()
        call_kwargs = mock_analyse.call_args[1]
        assert call_kwargs["target_file"] == str(payload)

    def test_normal_run_prints_mpcmdrun_path(self, tmp_path, capsys):
        payload = tmp_path / "payload.exe"
        payload.write_bytes(b"\x00" * 10)

        with patch("sys.argv", ["dc", str(payload)]):
            with patch("defender_check.cli.locate_mpcmdrun",
                       return_value="/custom/MpCmdRun.exe"):
                with patch("defender_check.cli.configure"):
                    with patch("defender_check.cli.analyse",
                               return_value=_make_report()):
                        main()

        assert "/custom/MpCmdRun.exe" in capsys.readouterr().out

    def test_json_flag_emits_valid_json(self, tmp_path, capsys):
        payload = tmp_path / "payload.exe"
        payload.write_bytes(b"\x00" * 10)
        mock_report = _make_report(hits=1, patched=str(tmp_path / "p.exe"), clean=True)

        with patch("sys.argv", ["dc", str(payload), "--json"]):
            with patch("defender_check.cli.locate_mpcmdrun",
                       return_value="/fake/MpCmdRun.exe"):
                with patch("defender_check.cli.configure"):
                    with patch("defender_check.cli.analyse",
                               return_value=mock_report):
                        main()

        out  = capsys.readouterr().out
        data = json.loads(out)   # raises if not valid JSON
        assert data["file_size"]   == 100
        assert data["engine_version"] == "1.0"
        assert len(data["hits"]) == 1

    def test_json_flag_suppresses_mpcmdrun_line(self, tmp_path, capsys):
        """When --json is active, only JSON should appear on stdout."""
        payload = tmp_path / "payload.exe"
        payload.write_bytes(b"\x00" * 10)

        with patch("sys.argv", ["dc", str(payload), "--json"]):
            with patch("defender_check.cli.locate_mpcmdrun",
                       return_value="/super/secret/MpCmdRun.exe"):
                with patch("defender_check.cli.configure"):
                    with patch("defender_check.cli.analyse",
                               return_value=_make_report()):
                        main()

        out = capsys.readouterr().out
        # MpCmdRun.exe path must NOT appear (would break JSON parsing)
        data = json.loads(out)   # fails if non-JSON output leaked
        assert "super" not in out.replace(json.dumps(data), "")

    def test_debug_flag_forwarded_to_analyse(self, tmp_path):
        payload = tmp_path / "payload.exe"
        payload.write_bytes(b"\x00" * 10)

        with patch("sys.argv", ["dc", str(payload), "--debug"]):
            with patch("defender_check.cli.locate_mpcmdrun",
                       return_value="/fake/MpCmdRun.exe"):
                with patch("defender_check.cli.configure"):
                    with patch("defender_check.cli.analyse",
                               return_value=_make_report()) as mock_analyse:
                        main()

        assert mock_analyse.call_args[1]["debug"] is True

    def test_no_sensitivity_flag_forwarded_to_analyse(self, tmp_path):
        payload = tmp_path / "payload.exe"
        payload.write_bytes(b"\x00" * 10)

        with patch("sys.argv", ["dc", str(payload), "--no-sensitivity"]):
            with patch("defender_check.cli.locate_mpcmdrun",
                       return_value="/fake/MpCmdRun.exe"):
                with patch("defender_check.cli.configure"):
                    with patch("defender_check.cli.analyse",
                               return_value=_make_report()) as mock_analyse:
                        main()

        assert mock_analyse.call_args[1]["no_sensitivity"] is True

    def test_configure_called_with_resolved_path(self, tmp_path):
        payload = tmp_path / "payload.exe"
        payload.write_bytes(b"\x00" * 10)

        with patch("sys.argv", ["dc", str(payload)]):
            with patch("defender_check.cli.locate_mpcmdrun",
                       return_value="/resolved/MpCmdRun.exe"):
                with patch("defender_check.cli.configure") as mock_configure:
                    with patch("defender_check.cli.analyse",
                               return_value=_make_report()):
                        main()

        mock_configure.assert_called_once_with("/resolved/MpCmdRun.exe")
