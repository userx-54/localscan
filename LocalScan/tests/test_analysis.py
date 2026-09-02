"""
test_analysis.py — tests for defender_check.analysis

Covers:
  - calc_entropy: empty, uniform, two-value, max-entropy, return type, bounds
  - entropy_note: all four buckets including boundary values
  - extract_strings: ASCII, UTF-16LE, length filtering, non-printable, mixed
  - pe_section_at: non-PE data, pefile-unavailable path, pefile-available mock
  - hex_dump: output format, non-printable substitution, multi-line, indent
"""

import math
import types
from unittest.mock import MagicMock, patch

import pytest

from defender_check.analysis import (
    _HAS_PEFILE,
    calc_entropy,
    entropy_note,
    extract_strings,
    hex_dump,
    pe_section_at,
)


# ── calc_entropy ──────────────────────────────────────────────────────────────

class TestCalcEntropy:
    def test_empty_bytes_returns_zero(self):
        assert calc_entropy(b"") == 0.0

    def test_single_repeated_byte_returns_zero(self):
        # Only one symbol → no uncertainty
        assert calc_entropy(b"\x00" * 200) == 0.0

    def test_two_equal_probability_bytes_returns_one(self):
        data = b"\x00\xFF" * 100
        assert abs(calc_entropy(data) - 1.0) < 1e-9

    def test_all_256_bytes_returns_eight(self):
        # Maximum possible entropy for a byte stream
        data = bytes(range(256))
        assert abs(calc_entropy(data) - 8.0) < 1e-9

    def test_returns_float(self):
        assert isinstance(calc_entropy(b"hello"), float)

    def test_entropy_in_valid_range(self):
        for data in [b"", b"A", b"\x00" * 10, bytes(range(256)), b"hello world"]:
            e = calc_entropy(data)
            assert 0.0 <= e <= 8.0, f"Entropy {e} out of range for {data!r}"

    def test_higher_diversity_gives_higher_entropy(self):
        uniform   = b"\x00" * 100                    # one symbol
        two_syms  = b"\x00\xFF" * 50                 # two symbols
        many_syms = bytes(range(100))                 # 100 different symbols
        assert calc_entropy(uniform) < calc_entropy(two_syms) < calc_entropy(many_syms)

    def test_single_byte_input(self):
        assert calc_entropy(b"\xAB") == 0.0

    def test_symmetric_around_distribution(self):
        # b"\x00\x01" and b"\x01\x00" should have the same entropy
        assert calc_entropy(b"\x00\x01") == calc_entropy(b"\x01\x00")


# ── entropy_note ──────────────────────────────────────────────────────────────

class TestEntropyNote:
    def test_above_7_is_high(self):
        assert "high" in entropy_note(7.1)
        assert "high" in entropy_note(8.0)

    def test_boundary_7_is_not_high(self):
        # e > 7.0, so exactly 7.0 should NOT be "high"
        assert "high" not in entropy_note(7.0)

    def test_above_5_below_7_is_medium(self):
        assert "medium" in entropy_note(5.5)
        assert "medium" in entropy_note(6.9)

    def test_below_3_is_low(self):
        assert "low" in entropy_note(0.0)
        assert "low" in entropy_note(2.9)

    def test_boundary_3_is_not_low(self):
        # e < 3.0, so exactly 3.0 should NOT be "low"
        assert "low" not in entropy_note(3.0)

    def test_between_3_and_5_is_moderate(self):
        assert "moderate" in entropy_note(3.0)
        assert "moderate" in entropy_note(4.0)
        assert "moderate" in entropy_note(5.0)

    def test_returns_string(self):
        assert isinstance(entropy_note(4.0), str)

    @pytest.mark.parametrize("value,expected_word", [
        (7.5, "high"),
        (6.0, "medium"),
        (1.0, "low"),
        (4.0, "moderate"),
    ])
    def test_parametrised_buckets(self, value, expected_word):
        assert expected_word in entropy_note(value)


# ── extract_strings ───────────────────────────────────────────────────────────

class TestExtractStrings:
    def test_empty_bytes_returns_empty_list(self):
        assert extract_strings(b"") == []

    def test_ascii_string_long_enough_is_found(self):
        assert "Hello" in extract_strings(b"Hello")

    def test_ascii_exactly_minimum_length_is_found(self):
        # _MIN_STR_LEN = 4
        result = extract_strings(b"test")
        assert "test" in result

    def test_ascii_below_minimum_length_not_found(self):
        assert extract_strings(b"Hi") == []
        assert extract_strings(b"abc") == []

    def test_non_printable_bytes_not_found(self):
        assert extract_strings(b"\x00\x01\x02\x03\x04\x05") == []

    def test_null_byte_terminates_string(self):
        # "hello\x00world" → two separate strings
        data = b"hello\x00world"
        result = extract_strings(data)
        assert "hello" in result
        assert "world" in result

    def test_utf16le_string_found(self):
        data = "Hello".encode("utf-16-le")
        result = extract_strings(data)
        assert "Hello" in result

    def test_utf16le_too_short_not_found(self):
        data = "Hi".encode("utf-16-le")   # only 2 chars → below min length
        result = extract_strings(data)
        assert "Hi" not in result

    def test_printable_space_is_included(self):
        # 0x20 (space) is printable
        result = extract_strings(b"    test")
        assert any(len(s) >= 4 for s in result)

    def test_del_0x7f_not_included(self):
        # 0x7F is DEL and should not be considered printable
        result = extract_strings(b"\x7f\x7f\x7f\x7f\x7f")
        assert result == []

    def test_mixed_content_finds_both(self):
        data = b"AAAA\x00\x00\xDE\xAD\xBE\xEF\x00\x00BBBB"
        result = extract_strings(data)
        assert "AAAA" in result
        assert "BBBB" in result

    def test_returns_list(self):
        assert isinstance(extract_strings(b"hello world"), list)

    def test_long_string_found_completely(self):
        long_str = "A" * 100
        result = extract_strings(long_str.encode("ascii"))
        assert long_str in result


# ── pe_section_at ─────────────────────────────────────────────────────────────

class TestPeSectionAt:
    def test_non_pe_data_returns_none(self):
        # Random bytes that don't start with MZ
        result = pe_section_at(b"\x00" * 200, 100)
        assert result is None

    def test_pefile_unavailable_returns_none(self):
        with patch("defender_check.analysis._HAS_PEFILE", False):
            # Even if data looks like a PE header, returns None without pefile
            result = pe_section_at(b"MZ" + b"\x00" * 500, 100)
        assert result is None

    def test_pefile_available_section_found(self):
        import defender_check.analysis as analysis_mod

        mock_pe = MagicMock()
        mock_section = MagicMock()
        mock_section.PointerToRawData = 0x400
        mock_section.SizeOfRawData    = 0x200
        mock_section.Name             = b".text\x00\x00\x00"
        mock_pe.sections              = [mock_section]

        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = mock_pe
        mock_pefile.PEFormatError   = Exception

        with patch("defender_check.analysis._HAS_PEFILE", True):
            with patch.object(analysis_mod, "pefile", mock_pefile, create=True):
                result = pe_section_at(b"MZ" + b"\x00" * 1024, 0x500)

        assert result == ".text"

    def test_pefile_available_offset_outside_sections(self):
        import defender_check.analysis as analysis_mod

        mock_pe = MagicMock()
        mock_section = MagicMock()
        mock_section.PointerToRawData = 0x400
        mock_section.SizeOfRawData    = 0x100
        mock_pe.sections              = [mock_section]

        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = mock_pe
        mock_pefile.PEFormatError   = Exception

        with patch("defender_check.analysis._HAS_PEFILE", True):
            with patch.object(analysis_mod, "pefile", mock_pefile, create=True):
                result = pe_section_at(b"MZ" + b"\x00" * 1024, 0x50)  # before .text

        assert result == "(outside all sections)"

    def test_pefile_format_error_returns_none(self):
        import defender_check.analysis as analysis_mod

        class FakePEError(Exception):
            pass

        mock_pefile = MagicMock()
        mock_pefile.PEFormatError  = FakePEError
        mock_pefile.PE.side_effect = FakePEError("not a PE")

        with patch("defender_check.analysis._HAS_PEFILE", True):
            with patch.object(analysis_mod, "pefile", mock_pefile, create=True):
                result = pe_section_at(b"\x00" * 100, 50)

        assert result is None


# ── hex_dump ──────────────────────────────────────────────────────────────────

class TestHexDump:
    def test_empty_data_produces_no_output(self, capsys):
        hex_dump(b"")
        assert capsys.readouterr().out == ""

    def test_offset_column_present(self, capsys):
        hex_dump(b"A" * 4)
        out = capsys.readouterr().out
        assert "00000000" in out

    def test_hex_values_present(self, capsys):
        hex_dump(b"\xDE\xAD\xBE\xEF")
        out = capsys.readouterr().out
        # The four bytes should appear as hex digits
        assert "DE" in out
        assert "AD" in out
        assert "BE" in out
        assert "EF" in out

    def test_printable_byte_shown_in_ascii_column(self, capsys):
        hex_dump(b"AAAA")
        out = capsys.readouterr().out
        # "A" should appear in the ASCII column
        assert "AAAA" in out

    def test_non_printable_byte_shown_as_middle_dot(self, capsys):
        hex_dump(b"\x01\x02\x03\x04")
        out = capsys.readouterr().out
        assert "·" in out

    def test_space_boundary_printable(self, capsys):
        # 0x20 (space) is printable, 0x1F is not
        hex_dump(b"\x1F ")
        out = capsys.readouterr().out
        assert "·" in out    # 0x1F → middle dot
        assert " " in out    # 0x20 → literal space in ASCII column

    def test_tilde_boundary_printable(self, capsys):
        # 0x7E (~) is printable, 0x7F is not
        hex_dump(b"~\x7F")
        out = capsys.readouterr().out
        assert "~" in out
        assert "·" in out

    def test_16_bytes_produces_one_line(self, capsys):
        hex_dump(b"A" * 16)
        out = capsys.readouterr().out
        data_lines = [l for l in out.strip().splitlines() if l.strip()]
        assert len(data_lines) == 1

    def test_17_bytes_produces_two_lines(self, capsys):
        hex_dump(b"A" * 17)
        out = capsys.readouterr().out
        data_lines = [l for l in out.strip().splitlines() if l.strip()]
        assert len(data_lines) == 2

    def test_second_line_has_correct_offset(self, capsys):
        hex_dump(b"A" * 32)   # two full lines of 16
        out = capsys.readouterr().out
        assert "00000010" in out   # offset 16 in hex

    def test_custom_indent(self, capsys):
        hex_dump(b"test", indent=8)
        out = capsys.readouterr().out
        # First non-newline character should be a space (part of the indent)
        assert out.startswith(" " * 8)

    def test_default_indent_is_4(self, capsys):
        hex_dump(b"test")
        out = capsys.readouterr().out
        assert out.startswith("    ")
        assert not out.startswith("     ")   # not more than 4
