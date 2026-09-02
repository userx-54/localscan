"""
test_orchestrator.py — tests for defender_check.orchestrator

Covers:
  - _patch_working: full-window zeroing, surgical patch, surgical fallback
  - _write_outputs: no-hits guard, patched file created with correct content,
                    YARA file with all rules, clean_after_patching flag
  - analyse: clean file early exit, report metadata, single-hit flow,
             multi-hit flow, no_sensitivity flag respected
"""

import os
from unittest.mock import MagicMock, call, patch

import pytest

from defender_check import orchestrator
from defender_check.models import Hit, Report, ScanResult
from defender_check.orchestrator import _patch_working, _write_outputs


# ── Helpers ───────────────────────────────────────────────────────────────────

_NOOP_LOG = lambda msg="": None   # silent stand-in for the log() closure


def _make_hit(index=0, offset=50, yara_rule="rule X { condition: true }") -> Hit:
    return Hit(
        index=index,
        offset=offset,
        offset_hex=f"0x{offset:X}",
        signature="TestSig",
        pe_section=".text",
        entropy=5.0,
        entropy_note="medium — mixed content",
        strings=["bad"],
        load_bearing_offsets=[offset - 1],
        flagged_bytes_hex="AA BB",
        yara_rule=yara_rule,
    )


def _make_report(target_file: str) -> Report:
    return Report(
        target_file=target_file,
        file_size=100,
        engine_version="1.0",
        signature_version="2.0",
    )


# ── _patch_working ────────────────────────────────────────────────────────────

class TestPatchWorking:
    def test_no_load_bearing_zeroes_full_window(self):
        working      = bytearray(b"\xFF" * 20)
        region_start = 5
        bad_offset   = 15

        # scan not called when load_bearing is empty
        _patch_working(working, [], region_start, bad_offset, "/tmp/t.exe", _NOOP_LOG)

        assert all(b == 0x00 for b in working[5:15]),  "Window not zeroed"
        assert all(b == 0xFF for b in working[:5]),     "Bytes before window changed"
        assert all(b == 0xFF for b in working[15:]),    "Bytes after window changed"

    def test_surgical_patch_zeroes_only_load_bearing(self, tmp_path):
        working   = bytearray(b"\xFF" * 20)
        tf        = str(tmp_path / "t.exe")

        # surgical patch is sufficient → scan returns NO_THREAT
        with patch("defender_check.orchestrator.scan",
                   return_value=(ScanResult.NO_THREAT, None)):
            _patch_working(working, [7, 12], 5, 15, tf, _NOOP_LOG)

        assert working[7]  == 0x00, "Load-bearing byte 7 not zeroed"
        assert working[12] == 0x00, "Load-bearing byte 12 not zeroed"
        # Other bytes in the window should be untouched
        assert working[5]  == 0xFF
        assert working[8]  == 0xFF
        assert working[14] == 0xFF

    def test_surgical_fallback_when_patch_insufficient(self, tmp_path):
        working      = bytearray(b"\xFF" * 20)
        tf           = str(tmp_path / "t.exe")
        region_start = 5
        bad_offset   = 15

        # surgical patch is not sufficient → scan still returns THREAT
        with patch("defender_check.orchestrator.scan",
                   return_value=(ScanResult.THREAT, None)):
            _patch_working(working, [7], region_start, bad_offset, tf, _NOOP_LOG)

        # Full window must be zeroed after fallback
        assert all(b == 0x00 for b in working[region_start:bad_offset])

    def test_surgical_patch_writes_working_to_test_file(self, tmp_path):
        """After the surgical patch, _patch_working writes working to test_file for verification."""
        working = bytearray(b"\xFF" * 10)
        tf      = str(tmp_path / "t.exe")

        with patch("defender_check.orchestrator.scan",
                   return_value=(ScanResult.NO_THREAT, None)):
            _patch_working(working, [5], 3, 8, tf, _NOOP_LOG)

        with open(tf, "rb") as fh:
            written = fh.read()
        assert written == bytes(working)

    def test_region_start_at_zero(self):
        working = bytearray(b"\xFF" * 10)
        _patch_working(working, [], 0, 5, "/tmp/t.exe", _NOOP_LOG)
        assert all(b == 0x00 for b in working[:5])
        assert all(b == 0xFF for b in working[5:])


# ── _write_outputs ────────────────────────────────────────────────────────────

class TestWriteOutputs:
    def test_no_hits_writes_nothing(self, tmp_path):
        payload = tmp_path / "payload.exe"
        payload.write_bytes(b"\xFF" * 100)
        report  = _make_report(str(payload))
        working = bytearray(b"\x00" * 100)

        with patch("defender_check.orchestrator.scan",
                   return_value=(ScanResult.NO_THREAT, None)):
            _write_outputs(report, working, str(payload), _NOOP_LOG)

        assert report.patched_file is None
        assert not (tmp_path / "payload_patched.exe").exists()

    def test_patched_file_created_next_to_original(self, tmp_path):
        payload = tmp_path / "payload.exe"
        payload.write_bytes(b"\xFF" * 100)
        report  = _make_report(str(payload))
        report.hits.append(_make_hit())
        working = bytearray(b"\x00" * 100)

        with patch("defender_check.orchestrator.scan",
                   return_value=(ScanResult.NO_THREAT, None)):
            _write_outputs(report, working, str(payload), _NOOP_LOG)

        assert (tmp_path / "payload_patched.exe").exists()
        assert report.patched_file == str(tmp_path / "payload_patched.exe")

    def test_patched_file_contains_working_bytes(self, tmp_path):
        payload = tmp_path / "payload.exe"
        payload.write_bytes(b"\xFF" * 100)
        report  = _make_report(str(payload))
        report.hits.append(_make_hit())
        working = bytearray(b"\xAB" * 100)

        with patch("defender_check.orchestrator.scan",
                   return_value=(ScanResult.NO_THREAT, None)):
            _write_outputs(report, working, str(payload), _NOOP_LOG)

        assert (tmp_path / "payload_patched.exe").read_bytes() == bytes(working)

    def test_yara_file_created(self, tmp_path):
        payload = tmp_path / "payload.exe"
        payload.write_bytes(b"\xFF" * 100)
        report  = _make_report(str(payload))
        report.hits.append(_make_hit())

        with patch("defender_check.orchestrator.scan",
                   return_value=(ScanResult.NO_THREAT, None)):
            _write_outputs(report, bytearray(100), str(payload), _NOOP_LOG)

        assert (tmp_path / "payload_signatures.yar").exists()

    def test_yara_file_contains_all_rules(self, tmp_path):
        payload = tmp_path / "payload.exe"
        payload.write_bytes(b"\xFF" * 100)
        report  = _make_report(str(payload))
        report.hits.append(_make_hit(index=0, yara_rule="rule Hit0 { condition: true }"))
        report.hits.append(_make_hit(index=1, yara_rule="rule Hit1 { condition: true }"))

        with patch("defender_check.orchestrator.scan",
                   return_value=(ScanResult.NO_THREAT, None)):
            _write_outputs(report, bytearray(100), str(payload), _NOOP_LOG)

        content = (tmp_path / "payload_signatures.yar").read_text()
        assert "rule Hit0" in content
        assert "rule Hit1" in content

    def test_clean_after_patching_true_when_scan_clean(self, tmp_path):
        payload = tmp_path / "payload.exe"
        payload.write_bytes(b"\xFF" * 100)
        report  = _make_report(str(payload))
        report.hits.append(_make_hit())

        with patch("defender_check.orchestrator.scan",
                   return_value=(ScanResult.NO_THREAT, None)):
            _write_outputs(report, bytearray(100), str(payload), _NOOP_LOG)

        assert report.clean_after_patching is True

    def test_clean_after_patching_false_when_scan_still_flagged(self, tmp_path):
        payload = tmp_path / "payload.exe"
        payload.write_bytes(b"\xFF" * 100)
        report  = _make_report(str(payload))
        report.hits.append(_make_hit())

        with patch("defender_check.orchestrator.scan",
                   return_value=(ScanResult.THREAT, None)):
            _write_outputs(report, bytearray(100), str(payload), _NOOP_LOG)

        assert report.clean_after_patching is False


# ── analyse ───────────────────────────────────────────────────────────────────

class TestAnalyse:
    """
    Integration tests for analyse().

    scan, binary_search, sensitivity_analysis, and get_defender_info are all
    mocked so we can drive the control flow deterministically without touching
    the filesystem beyond the temporary target file.
    """

    def _run(self, payload_path, scan_seq, bs_seq,
             no_sensitivity=True, quiet=True):
        """
        Run analyse() with controlled mocks.

        scan_seq  : list of (ScanResult, sig_name) returned in order
        bs_seq    : list of ints returned by binary_search in order
        """
        scan_iter = iter(scan_seq)
        bs_iter   = iter(bs_seq)

        with patch("defender_check.orchestrator.scan",
                   side_effect=lambda *a, **k: next(scan_iter)):
            with patch("defender_check.orchestrator.get_defender_info",
                       return_value=("engine-1.0", "sig-2.0")):
                with patch("defender_check.orchestrator.binary_search",
                           side_effect=lambda *a, **k: next(bs_iter)):
                    with patch("defender_check.orchestrator.sensitivity_analysis",
                               return_value=[]):
                        return orchestrator.analyse(
                            str(payload_path),
                            no_sensitivity=no_sensitivity,
                            quiet=quiet,
                        )

    # ── Metadata ──────────────────────────────────────────────────────────────

    def test_report_stores_file_size(self, tmp_path):
        payload = tmp_path / "p.exe"
        payload.write_bytes(b"\x00" * 42)

        report = self._run(
            payload,
            scan_seq=[(ScanResult.NO_THREAT, None)],
            bs_seq=[],
        )
        assert report.file_size == 42

    def test_report_stores_version_info(self, tmp_path):
        payload = tmp_path / "p.exe"
        payload.write_bytes(b"\x00" * 10)

        report = self._run(
            payload,
            scan_seq=[(ScanResult.NO_THREAT, None)],
            bs_seq=[],
        )
        assert report.engine_version    == "engine-1.0"
        assert report.signature_version == "sig-2.0"

    def test_report_stores_target_file(self, tmp_path):
        payload = tmp_path / "p.exe"
        payload.write_bytes(b"\x00" * 10)

        report = self._run(
            payload,
            scan_seq=[(ScanResult.NO_THREAT, None)],
            bs_seq=[],
        )
        assert report.target_file == str(payload)

    # ── Early exit: clean file ────────────────────────────────────────────────

    def test_clean_file_returns_no_hits(self, tmp_path):
        payload = tmp_path / "p.exe"
        payload.write_bytes(b"\x00" * 50)

        report = self._run(
            payload,
            scan_seq=[(ScanResult.NO_THREAT, None)],
            bs_seq=[],
        )
        assert report.hits == []
        assert report.patched_file is None

    def test_error_scan_result_returns_no_hits(self, tmp_path):
        payload = tmp_path / "p.exe"
        payload.write_bytes(b"\x00" * 50)

        report = self._run(
            payload,
            scan_seq=[(ScanResult.ERROR, None)],
            bs_seq=[],
        )
        assert report.hits == []

    # ── Single hit ────────────────────────────────────────────────────────────

    def test_single_hit_recorded(self, tmp_path):
        payload = tmp_path / "p.exe"
        payload.write_bytes(b"\x00" * 100)

        # Scan sequence for no_sensitivity=True:
        #   1. initial check          → THREAT
        #   2. sig name extraction    → (THREAT, "TestSig")
        #   3. post-patch check       → NO_THREAT  (exits loop)
        #   4. final patched scan     → NO_THREAT
        report = self._run(
            payload,
            scan_seq=[
                (ScanResult.THREAT, None),
                (ScanResult.THREAT, "TestSig"),
                (ScanResult.NO_THREAT, None),
                (ScanResult.NO_THREAT, None),
            ],
            bs_seq=[90],
        )
        assert len(report.hits) == 1
        assert report.hits[0].offset    == 90
        assert report.hits[0].signature == "TestSig"

    def test_single_hit_patched_file_created(self, tmp_path):
        payload = tmp_path / "p.exe"
        payload.write_bytes(b"\x00" * 100)

        report = self._run(
            payload,
            scan_seq=[
                (ScanResult.THREAT, None),
                (ScanResult.THREAT, "TestSig"),
                (ScanResult.NO_THREAT, None),
                (ScanResult.NO_THREAT, None),
            ],
            bs_seq=[90],
        )
        assert report.patched_file is not None
        assert os.path.exists(report.patched_file)

    def test_single_hit_clean_after_patching(self, tmp_path):
        payload = tmp_path / "p.exe"
        payload.write_bytes(b"\x00" * 100)

        report = self._run(
            payload,
            scan_seq=[
                (ScanResult.THREAT, None),
                (ScanResult.THREAT, "TestSig"),
                (ScanResult.NO_THREAT, None),
                (ScanResult.NO_THREAT, None),
            ],
            bs_seq=[90],
        )
        assert report.clean_after_patching is True

    # ── Multi-hit ─────────────────────────────────────────────────────────────

    def test_two_hits_both_recorded(self, tmp_path):
        payload = tmp_path / "p.exe"
        payload.write_bytes(b"\x00" * 200)

        # Two binary_search calls return offsets 80 and 160.
        # Scan sequence:
        #   1. initial check              → THREAT
        #   2. sig name (hit 0)           → (THREAT, "Sig0")
        #   3. post-patch (hit 0)         → THREAT  (more hits remain)
        #   4. sig name (hit 1)           → (THREAT, "Sig1")
        #   5. post-patch (hit 1)         → NO_THREAT
        #   6. final patched scan         → NO_THREAT
        report = self._run(
            payload,
            scan_seq=[
                (ScanResult.THREAT, None),
                (ScanResult.THREAT, "Sig0"),
                (ScanResult.THREAT, None),
                (ScanResult.THREAT, "Sig1"),
                (ScanResult.NO_THREAT, None),
                (ScanResult.NO_THREAT, None),
            ],
            bs_seq=[80, 160],
        )
        assert len(report.hits) == 2
        assert report.hits[0].offset == 80
        assert report.hits[1].offset == 160

    # ── Flags ─────────────────────────────────────────────────────────────────

    def test_no_sensitivity_skips_sensitivity_analysis(self, tmp_path):
        payload = tmp_path / "p.exe"
        payload.write_bytes(b"\x00" * 100)

        with patch("defender_check.orchestrator.sensitivity_analysis") as mock_sa:
            self._run(
                payload,
                scan_seq=[
                    (ScanResult.THREAT, None),
                    (ScanResult.THREAT, "Sig"),
                    (ScanResult.NO_THREAT, None),
                    (ScanResult.NO_THREAT, None),
                ],
                bs_seq=[90],
                no_sensitivity=True,
            )
        mock_sa.assert_not_called()
