"""
test_yara_gen.py — tests for defender_check.yara_gen

Covers:
  - _build_hex_pattern: wildcard placement with load_bearing, verbatim fallback,
                        128-byte cap, correct absolute-offset mapping
  - _build_string_decls: string count cap, $sig always last, escape sequences
  - _build_description: index, optional sig_name inclusion
  - generate_yara: valid structure, rule name, date, condition logic,
                   with/without strings, with/without load_bearing
"""

import datetime
import re
from typing import Optional

import pytest

from defender_check.yara_gen import (
    _build_description,
    _build_hex_pattern,
    _build_string_decls,
    generate_yara,
)


# ── _build_hex_pattern ────────────────────────────────────────────────────────

class TestBuildHexPattern:
    def test_with_load_bearing_keeps_values(self):
        flagged      = bytes([0xAA, 0xBB, 0xCC, 0xDD])
        load_bearing = [0, 2]   # absolute offsets (region_start = 0)
        pattern      = _build_hex_pattern(flagged, 0, load_bearing)
        tokens       = pattern.split()

        assert tokens[0] == "aa"   # load-bearing → actual value
        assert tokens[1] == "??"   # not load-bearing → wildcard
        assert tokens[2] == "cc"   # load-bearing → actual value
        assert tokens[3] == "??"   # not load-bearing → wildcard

    def test_with_load_bearing_correct_token_count(self):
        flagged      = bytes(range(10))
        load_bearing = [0, 5, 9]
        pattern      = _build_hex_pattern(flagged, 0, load_bearing)
        assert len(pattern.split()) == 10

    def test_all_load_bearing_no_wildcards(self):
        flagged      = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        load_bearing = [0, 1, 2, 3]
        pattern      = _build_hex_pattern(flagged, 0, load_bearing)
        assert "??" not in pattern
        assert pattern == "de ad be ef"

    def test_no_load_bearing_uses_last_128_bytes(self):
        # 200 bytes: indices 0–199; last 128 are indices 72–199
        flagged = bytes(range(200))
        pattern = _build_hex_pattern(flagged, 0, [])
        tokens  = pattern.split()

        assert len(tokens) == 128
        assert tokens[0]  == f"{72:02x}"
        assert tokens[-1] == f"{199:02x}"

    def test_no_load_bearing_short_data_uses_all_bytes(self):
        flagged = bytes([0x41, 0x42, 0x43])
        tokens  = _build_hex_pattern(flagged, 0, []).split()
        assert tokens == ["41", "42", "43"]

    def test_nonzero_region_start_maps_offsets_correctly(self):
        """Absolute offset 101 == local index 1 when region_start = 100."""
        flagged      = bytes([0x10, 0x20, 0x30])
        region_start = 100
        load_bearing = [101]   # absolute offset 101 → local index 1

        tokens = _build_hex_pattern(flagged, region_start, load_bearing).split()
        assert tokens[0] == "??"   # abs 100: not load-bearing
        assert tokens[1] == "20"   # abs 101: load-bearing
        assert tokens[2] == "??"   # abs 102: not load-bearing

    def test_load_bearing_offset_beyond_region_treated_as_not_present(self):
        """An offset outside the region should not accidentally match."""
        flagged      = bytes([0xAA, 0xBB])
        load_bearing = [999]   # well outside region_start=0 + len=2
        tokens       = _build_hex_pattern(flagged, 0, load_bearing).split()
        assert tokens == ["??", "??"]   # neither byte is load-bearing

    def test_returns_string(self):
        assert isinstance(_build_hex_pattern(b"\x00", 0, []), str)

    def test_hex_digits_are_lowercase(self):
        flagged = bytes([0xAB, 0xCD])
        pattern = _build_hex_pattern(flagged, 0, [0, 1])
        assert pattern == "ab cd"


# ── _build_string_decls ───────────────────────────────────────────────────────

class TestBuildStringDecls:
    def test_empty_strings_only_has_sig_line(self):
        decls = _build_string_decls([], "aa bb cc")
        assert len(decls) == 1
        assert "$sig" in decls[0]
        assert "aa bb cc" in decls[0]

    def test_strings_become_str_variables(self):
        decls = _build_string_decls(["hello", "world"], "aa")
        str_decls = [d for d in decls if "$str" in d]
        assert any('"hello"' in d for d in str_decls)
        assert any('"world"' in d for d in str_decls)

    def test_str_variables_numbered_from_zero(self):
        decls = _build_string_decls(["a", "b", "c"], "00")
        assert any("$str0" in d for d in decls)
        assert any("$str1" in d for d in decls)
        assert any("$str2" in d for d in decls)

    def test_capped_at_five_strings(self):
        strings = [f"string_{i}" * 2 for i in range(8)]
        decls   = _build_string_decls(strings, "aa")
        str_decls = [d for d in decls if "$str" in d]
        assert len(str_decls) == 5

    def test_sig_is_always_last(self):
        decls = _build_string_decls(["hello", "world"], "de ad")
        assert "$sig" in decls[-1]

    def test_backslash_escaped_in_string(self):
        decls = _build_string_decls([r"C:\Windows\System32"], "aa")
        assert r"C:\\Windows\\System32" in decls[0]

    def test_double_quote_escaped(self):
        decls = _build_string_decls(['say "hello"'], "aa")
        assert '\\"hello\\"' in decls[0]

    def test_returns_list(self):
        assert isinstance(_build_string_decls([], "aa"), list)

    def test_each_entry_is_indented(self):
        for decl in _build_string_decls(["test"], "aa"):
            assert decl.startswith(" "), f"Declaration not indented: {decl!r}"


# ── _build_description ────────────────────────────────────────────────────────

class TestBuildDescription:
    def test_contains_hit_index(self):
        for i in [0, 1, 5, 42]:
            assert str(i) in _build_description(i, None)

    def test_without_sig_name(self):
        desc = _build_description(0, None)
        assert isinstance(desc, str)
        assert len(desc) > 0

    def test_sig_name_appended(self):
        desc = _build_description(1, "Trojan:Win32/Mimikatz")
        assert "Trojan:Win32/Mimikatz" in desc

    def test_without_sig_name_no_parentheses_from_name(self):
        desc = _build_description(0, None)
        # The sig name parenthetical should not appear
        assert "(None)" not in desc


# ── generate_yara ─────────────────────────────────────────────────────────────

def make_rule(
    index:         int  = 0,
    region_start:  int  = 0,
    flagged_bytes: bytes = bytes(range(16)),
    strings:       list = None,
    sig_name:      Optional[str] = None,
    load_bearing:  list = None,
) -> str:
    return generate_yara(
        index        = index,
        region_start = region_start,
        flagged_bytes= flagged_bytes,
        strings      = strings or [],
        sig_name     = sig_name,
        load_bearing = load_bearing or [],
    )


class TestGenerateYara:
    # ── Structure ─────────────────────────────────────────────────────────────

    def test_rule_starts_with_rule_keyword(self):
        assert make_rule().strip().startswith("rule ")

    def test_rule_ends_with_closing_brace(self):
        assert make_rule().strip().endswith("}")

    def test_contains_meta_section(self):
        rule = make_rule()
        assert "meta:" in rule

    def test_contains_strings_section(self):
        rule = make_rule()
        assert "strings:" in rule

    def test_contains_condition_section(self):
        rule = make_rule()
        assert "condition:" in rule

    def test_contains_sig_variable(self):
        assert "$sig" in make_rule()

    # ── Naming and metadata ───────────────────────────────────────────────────

    def test_rule_name_includes_index(self):
        for i in range(5):
            assert f"DefenderCheck_Hit_{i}" in make_rule(index=i)

    def test_description_in_meta(self):
        assert "description" in make_rule()

    def test_date_is_today(self):
        assert str(datetime.date.today()) in make_rule()

    def test_sig_name_in_rule_when_provided(self):
        assert "Trojan:Win32/Test" in make_rule(sig_name="Trojan:Win32/Test")

    # ── Condition logic ───────────────────────────────────────────────────────

    def test_no_strings_condition_is_sig_only(self):
        rule  = make_rule(strings=[])
        lines = rule.splitlines()
        cond_idx  = next(i for i, l in enumerate(lines) if "condition:" in l)
        cond_body = lines[cond_idx + 1]
        assert "$sig" in cond_body
        assert "any of ($str*)" not in cond_body

    def test_with_strings_condition_includes_str_wildcard(self):
        rule  = make_rule(strings=["hello"])
        lines = rule.splitlines()
        cond_idx  = next(i for i, l in enumerate(lines) if "condition:" in l)
        cond_body = lines[cond_idx + 1]
        assert "any of ($str*)" in cond_body

    def test_with_strings_condition_still_includes_sig(self):
        rule  = make_rule(strings=["hello"])
        lines = rule.splitlines()
        cond_idx  = next(i for i, l in enumerate(lines) if "condition:" in l)
        cond_body = lines[cond_idx + 1]
        assert "$sig" in cond_body

    # ── Hex pattern integration ───────────────────────────────────────────────

    def test_load_bearing_bytes_in_hex_pattern(self):
        flagged      = bytes([0xAA, 0xBB, 0xCC])
        load_bearing = [1]   # absolute offset 1 → local index 1 (0xBB)
        rule         = make_rule(flagged_bytes=flagged, load_bearing=load_bearing)
        assert "bb" in rule
        assert "??" in rule   # non-load-bearing bytes become wildcards

    def test_no_load_bearing_uses_verbatim_bytes(self):
        flagged = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        rule    = make_rule(flagged_bytes=flagged, load_bearing=[])
        assert "??" not in rule   # fallback = verbatim, no wildcards
        assert "de" in rule

    # ── String declarations ───────────────────────────────────────────────────

    def test_strings_appear_in_rule(self):
        rule = make_rule(strings=["bad_func", "evil_url"])
        assert "bad_func" in rule
        assert "evil_url" in rule

    def test_more_than_five_strings_capped(self):
        rule = make_rule(strings=[f"str{i}" for i in range(10)])
        # Only $str0 through $str4 should appear
        assert "$str4" in rule
        assert "$str5" not in rule

    # ── Return type ───────────────────────────────────────────────────────────

    def test_returns_string(self):
        assert isinstance(make_rule(), str)

    def test_rule_is_not_empty(self):
        assert len(make_rule()) > 0
