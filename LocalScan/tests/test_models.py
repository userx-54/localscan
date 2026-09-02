"""
test_models.py — tests for defender_check.models

Covers:
  - ScanResult constant values and uniqueness
  - Hit dataclass fields, defaults, and Optional handling
  - Report dataclass defaults and dataclasses.asdict serialisability
"""

from dataclasses import asdict

import pytest

from defender_check.models import Hit, Report, ScanResult


# ── ScanResult ────────────────────────────────────────────────────────────────

class TestScanResult:
    def test_no_threat_value(self):
        assert ScanResult.NO_THREAT == "NoThreatFound"

    def test_threat_value(self):
        assert ScanResult.THREAT == "ThreatFound"

    def test_not_found_value(self):
        assert ScanResult.NOT_FOUND == "FileNotFound"

    def test_timeout_value(self):
        assert ScanResult.TIMEOUT == "Timeout"

    def test_error_value(self):
        assert ScanResult.ERROR == "Error"

    def test_all_constants_are_distinct(self):
        values = [
            ScanResult.NO_THREAT,
            ScanResult.THREAT,
            ScanResult.NOT_FOUND,
            ScanResult.TIMEOUT,
            ScanResult.ERROR,
        ]
        assert len(set(values)) == len(values), "ScanResult constants must all be unique"

    def test_constants_are_strings(self):
        for val in [ScanResult.NO_THREAT, ScanResult.THREAT,
                    ScanResult.NOT_FOUND, ScanResult.TIMEOUT, ScanResult.ERROR]:
            assert isinstance(val, str)


# ── Hit ───────────────────────────────────────────────────────────────────────

def _make_hit(**overrides) -> Hit:
    defaults = dict(
        index=0,
        offset=256,
        offset_hex="0x100",
        signature="Trojan:Win32/TestSig",
        pe_section=".text",
        entropy=5.5,
        entropy_note="medium — mixed content",
        strings=["bad_string"],
        load_bearing_offsets=[254, 255],
        flagged_bytes_hex="DE AD BE EF",
        yara_rule="rule X { condition: true }",
    )
    defaults.update(overrides)
    return Hit(**defaults)


class TestHit:
    def test_all_fields_stored(self):
        hit = _make_hit()
        assert hit.index == 0
        assert hit.offset == 256
        assert hit.offset_hex == "0x100"
        assert hit.signature == "Trojan:Win32/TestSig"
        assert hit.pe_section == ".text"
        assert hit.entropy == 5.5
        assert hit.strings == ["bad_string"]
        assert hit.load_bearing_offsets == [254, 255]
        assert hit.flagged_bytes_hex == "DE AD BE EF"

    def test_signature_can_be_none(self):
        hit = _make_hit(signature=None)
        assert hit.signature is None

    def test_pe_section_can_be_none(self):
        hit = _make_hit(pe_section=None)
        assert hit.pe_section is None

    def test_strings_can_be_empty(self):
        hit = _make_hit(strings=[])
        assert hit.strings == []

    def test_load_bearing_can_be_empty(self):
        hit = _make_hit(load_bearing_offsets=[])
        assert hit.load_bearing_offsets == []

    def test_asdict_produces_expected_keys(self):
        d = asdict(_make_hit())
        expected_keys = {
            "index", "offset", "offset_hex", "signature", "pe_section",
            "entropy", "entropy_note", "strings", "load_bearing_offsets",
            "flagged_bytes_hex", "yara_rule",
        }
        assert set(d.keys()) == expected_keys

    def test_asdict_is_json_serialisable(self):
        import json
        d = asdict(_make_hit())
        # Should not raise
        json.dumps(d)

    def test_index_monotonicity_is_caller_responsibility(self):
        """Hit doesn't enforce ordering; the caller tracks index."""
        hits = [_make_hit(index=i) for i in [0, 1, 2]]
        assert [h.index for h in hits] == [0, 1, 2]


# ── Report ────────────────────────────────────────────────────────────────────

def _make_report(**overrides) -> Report:
    defaults = dict(
        target_file="payload.exe",
        file_size=1024,
        engine_version="4.18.0.0",
        signature_version="1.400.0.0",
    )
    defaults.update(overrides)
    return Report(**defaults)


class TestReport:
    def test_hits_default_is_empty_list(self):
        r = _make_report()
        assert r.hits == []

    def test_hits_default_not_shared_between_instances(self):
        """dataclass field(default_factory=list) must give each instance its own list."""
        r1 = _make_report()
        r2 = _make_report()
        r1.hits.append(_make_hit())
        assert r2.hits == [], "Mutable default was shared between Report instances"

    def test_patched_file_default_is_none(self):
        assert _make_report().patched_file is None

    def test_clean_after_patching_default_is_false(self):
        assert _make_report().clean_after_patching is False

    def test_stores_target_file(self):
        r = _make_report(target_file="/some/path/payload.exe")
        assert r.target_file == "/some/path/payload.exe"

    def test_stores_file_size(self):
        assert _make_report(file_size=4096).file_size == 4096

    def test_stores_version_info(self):
        r = _make_report(engine_version="1.2.3.4", signature_version="5.6.7.8")
        assert r.engine_version == "1.2.3.4"
        assert r.signature_version == "5.6.7.8"

    def test_patched_file_can_be_set(self):
        r = _make_report()
        r.patched_file = "/out/payload_patched.exe"
        assert r.patched_file == "/out/payload_patched.exe"

    def test_asdict_includes_hits(self):
        r = _make_report()
        r.hits.append(_make_hit())
        d = asdict(r)
        assert len(d["hits"]) == 1
        assert d["hits"][0]["index"] == 0

    def test_asdict_is_json_serialisable(self):
        import json
        r = _make_report()
        r.hits.append(_make_hit())
        r.patched_file = "/out/patched.exe"
        r.clean_after_patching = True
        json.dumps(asdict(r))  # must not raise
