"""
test_search.py — tests for defender_check.search

Covers:
  - binary_search: correct convergence for various threat positions,
                   file-slice writes, timeout handling, single-byte data
  - sensitivity_analysis: load-bearing detection, empty result, absolute
                          offsets, window boundaries, byte flip mechanics
  - WINDOW constant is exported with expected value
"""

from unittest.mock import patch

import pytest

from defender_check.models import ScanResult
from defender_check.search import WINDOW, binary_search, sensitivity_analysis


# ── Helpers ───────────────────────────────────────────────────────────────────

def threshold_scan(threshold: int):
    """
    Return a scan function that flags any file whose content length >= threshold.

    This lets us precisely control which prefix sizes trigger a detection,
    making binary_search convergence deterministic and verifiable.
    """
    def _scan(filepath, get_sig=False):
        with open(filepath, "rb") as fh:
            n = len(fh.read())
        return (
            (ScanResult.THREAT, None) if n >= threshold
            else (ScanResult.NO_THREAT, None)
        )
    return _scan


def single_byte_scan(target_abs_offset: int, original_value: int):
    """
    Return a scan function that flags unless byte[target_abs_offset] is flipped.

    Used to test sensitivity_analysis: flipping the byte at target_abs_offset
    should make the scan return NO_THREAT.
    """
    def _scan(filepath, get_sig=False):
        with open(filepath, "rb") as fh:
            data = fh.read()
        if len(data) <= target_abs_offset:
            return (ScanResult.NO_THREAT, None)
        status = (
            ScanResult.NO_THREAT if data[target_abs_offset] != original_value
            else ScanResult.THREAT
        )
        return (status, None)
    return _scan


# ── binary_search ─────────────────────────────────────────────────────────────

class TestBinarySearch:
    def test_threat_at_first_byte(self, tmp_path):
        data = b"\x00" * 10
        tf   = str(tmp_path / "t.exe")
        with patch("defender_check.search.scan", threshold_scan(1)):
            assert binary_search(data, tf) == 1

    def test_threat_at_last_byte(self, tmp_path):
        data = b"\x00" * 10
        tf   = str(tmp_path / "t.exe")
        with patch("defender_check.search.scan", threshold_scan(10)):
            assert binary_search(data, tf) == 10

    def test_threat_at_exact_midpoint(self, tmp_path):
        data = b"\x00" * 16
        tf   = str(tmp_path / "t.exe")
        with patch("defender_check.search.scan", threshold_scan(8)):
            assert binary_search(data, tf) == 8

    @pytest.mark.parametrize("threshold", range(1, 17))
    def test_converges_to_correct_threshold(self, tmp_path, threshold):
        """The returned offset equals the threshold for every value 1–16."""
        data = b"\x00" * 16
        tf   = str(tmp_path / "t.exe")
        with patch("defender_check.search.scan", threshold_scan(threshold)):
            assert binary_search(data, tf) == threshold

    def test_single_byte_data(self, tmp_path):
        tf = str(tmp_path / "t.exe")
        with patch("defender_check.search.scan", threshold_scan(1)):
            assert binary_search(b"\xFF", tf) == 1

    def test_writes_correct_prefix_to_test_file(self, tmp_path):
        """Each scan call must receive exactly data[:mid], not something else."""
        data    = b"\xAA\xBB\xCC\xDD\xEE\xFF"
        tf      = str(tmp_path / "t.exe")
        written = []

        def capturing_scan(filepath, get_sig=False):
            with open(filepath, "rb") as fh:
                chunk = fh.read()
            written.append(chunk)
            return (ScanResult.THREAT, None) if len(chunk) >= 4 else (ScanResult.NO_THREAT, None)

        with patch("defender_check.search.scan", capturing_scan):
            binary_search(data, tf)

        # Every written slice must be a valid prefix of data
        for chunk in written:
            assert data[: len(chunk)] == chunk, (
                f"Slice {chunk!r} is not a prefix of {data!r}"
            )

    def test_timeout_skips_midpoint_upward(self, tmp_path):
        """
        On timeout the search skips the problematic midpoint upward (lo = mid+1).
        The search must still terminate and return a value in [0, len(data)].
        """
        data      = b"\x00" * 8
        tf        = str(tmp_path / "t.exe")
        call_n    = [0]

        def flaky_scan(filepath, get_sig=False):
            call_n[0] += 1
            with open(filepath, "rb") as fh:
                n = len(fh.read())
            if call_n[0] <= 2:
                return (ScanResult.TIMEOUT, None)
            return (ScanResult.THREAT, None) if n >= 6 else (ScanResult.NO_THREAT, None)

        with patch("defender_check.search.scan", flaky_scan):
            result = binary_search(data, tf)

        assert 0 <= result <= len(data)

    def test_error_result_skips_upward(self, tmp_path):
        data = b"\x00" * 8
        tf   = str(tmp_path / "t.exe")
        call_n = [0]

        def error_then_normal(filepath, get_sig=False):
            call_n[0] += 1
            with open(filepath, "rb") as fh:
                n = len(fh.read())
            if call_n[0] == 1:
                return (ScanResult.ERROR, None)
            return (ScanResult.THREAT, None) if n >= 5 else (ScanResult.NO_THREAT, None)

        with patch("defender_check.search.scan", error_then_normal):
            result = binary_search(data, tf)

        assert 0 <= result <= len(data)

    def test_result_is_integer(self, tmp_path):
        tf = str(tmp_path / "t.exe")
        with patch("defender_check.search.scan", threshold_scan(3)):
            assert isinstance(binary_search(b"\x00" * 6, tf), int)

    def test_does_not_test_full_file_itself(self, tmp_path):
        """
        binary_search only tests strict prefixes (data[:mid] where mid < hi).
        It must never write the full file to test_file during the search loop.
        """
        data    = b"\x00" * 8
        tf      = str(tmp_path / "t.exe")
        lengths = []

        def recording_scan(filepath, get_sig=False):
            with open(filepath, "rb") as fh:
                lengths.append(len(fh.read()))
            return (ScanResult.THREAT, None) if lengths[-1] >= 4 else (ScanResult.NO_THREAT, None)

        with patch("defender_check.search.scan", recording_scan):
            binary_search(data, tf)

        # During the search loop, mid is always < hi = len(data), so
        # no slice of length len(data) should appear.
        assert len(data) not in lengths, (
            "binary_search wrote the full file during its search loop"
        )


# ── sensitivity_analysis ──────────────────────────────────────────────────────

class TestSensitivityAnalysis:
    def test_single_load_bearing_byte_detected(self, tmp_path, capsys):
        data     = b"\x00" * 10
        tf       = str(tmp_path / "t.exe")
        target   = 7  # absolute offset of the load-bearing byte

        with patch("defender_check.search.scan",
                   single_byte_scan(target, data[target])):
            result = sensitivity_analysis(data, 10, tf)

        assert target in result

    def test_no_load_bearing_bytes_returns_empty(self, tmp_path, capsys):
        data = b"\x00" * 10
        tf   = str(tmp_path / "t.exe")

        # Scan always returns THREAT → flipping any byte makes no difference
        with patch("defender_check.search.scan",
                   return_value=(ScanResult.THREAT, None)):
            result = sensitivity_analysis(data, 10, tf)

        assert result == []

    def test_multiple_load_bearing_bytes(self, tmp_path, capsys):
        """All bytes where flipping causes NO_THREAT should be in the result."""
        data      = b"\xAB" * 20
        tf        = str(tmp_path / "t.exe")
        load_offs = {5, 12, 19}

        def multi_sensitive(filepath, get_sig=False):
            with open(filepath, "rb") as fh:
                content = bytearray(fh.read())
            # Clean if any load-bearing byte has been flipped
            for off in load_offs:
                if off < len(content) and content[off] != 0xAB:
                    return (ScanResult.NO_THREAT, None)
            return (ScanResult.THREAT, None)

        with patch("defender_check.search.scan", multi_sensitive):
            result = sensitivity_analysis(data, 20, tf)

        assert load_offs.issubset(set(result))

    def test_returns_absolute_offsets_not_relative(self, tmp_path, capsys):
        """
        When bad_offset > WINDOW the region starts at bad_offset - WINDOW,
        so load-bearing offsets must be absolute (>= region_start).
        """
        data       = b"\x00" * 300   # bigger than WINDOW
        tf         = str(tmp_path / "t.exe")
        bad_offset = 300
        target     = 280              # absolute file offset

        with patch("defender_check.search.scan",
                   single_byte_scan(target, data[target])):
            result = sensitivity_analysis(data, bad_offset, tf)

        region_start = bad_offset - WINDOW
        assert target in result
        assert all(o >= region_start for o in result)

    def test_only_probes_bytes_within_window(self, tmp_path, capsys):
        """Bytes outside [bad_offset - WINDOW, bad_offset) must not be probed."""
        data       = b"\x00" * 300
        tf         = str(tmp_path / "t.exe")
        bad_offset = 300
        region_start = bad_offset - WINDOW
        probed     = []

        def recording_scan(filepath, get_sig=False):
            with open(filepath, "rb") as fh:
                content = bytearray(fh.read())
            # Find which byte was flipped (XOR 0xFF means it's now 0xFF)
            for i, b in enumerate(content):
                if b == 0xFF:
                    probed.append(i)
            return (ScanResult.THREAT, None)

        with patch("defender_check.search.scan", recording_scan):
            sensitivity_analysis(data, bad_offset, tf)

        for off in probed:
            assert region_start <= off < bad_offset, (
                f"Probed offset {off} is outside the window [{region_start}, {bad_offset})"
            )

    def test_flips_byte_by_xor_ff(self, tmp_path, capsys):
        """Each probe must flip the byte with XOR 0xFF, not set it to zero."""
        data   = b"\xAA" * 10   # 0xAA XOR 0xFF == 0x55
        tf     = str(tmp_path / "t.exe")
        seen_values = set()

        def value_recording_scan(filepath, get_sig=False):
            with open(filepath, "rb") as fh:
                content = fh.read()
            seen_values.update(content)
            return (ScanResult.THREAT, None)

        with patch("defender_check.search.scan", value_recording_scan):
            sensitivity_analysis(data, 10, tf)

        # 0x55 is 0xAA ^ 0xFF — this value should appear in the probes
        assert 0x55 in seen_values
        # 0x00 should NOT appear (we flip, not zero)
        assert 0x00 not in seen_values

    def test_returns_list_of_ints(self, tmp_path, capsys):
        data = b"\x00" * 8
        tf   = str(tmp_path / "t.exe")
        with patch("defender_check.search.scan",
                   single_byte_scan(4, data[4])):
            result = sensitivity_analysis(data, 8, tf)
        assert isinstance(result, list)
        assert all(isinstance(o, int) for o in result)


# ── WINDOW constant ───────────────────────────────────────────────────────────

class TestWindowConstant:
    def test_window_is_256(self):
        assert WINDOW == 256

    def test_window_is_exported(self):
        from defender_check.search import WINDOW as W
        assert W == 256
