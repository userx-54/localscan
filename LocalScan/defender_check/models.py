"""
models.py — shared data structures.

No internal dependencies; safe to import from anywhere in the package.
"""

from dataclasses import dataclass, field
from typing import Optional


class ScanResult:
    """String constants returned by scanner.scan()."""
    NO_THREAT = "NoThreatFound"
    THREAT    = "ThreatFound"
    NOT_FOUND = "FileNotFound"
    TIMEOUT   = "Timeout"
    ERROR     = "Error"


@dataclass
class Hit:
    """All data collected about one flagged region."""
    index:                int
    offset:               int
    offset_hex:           str
    signature:            Optional[str]
    pe_section:           Optional[str]
    entropy:              float
    entropy_note:         str
    strings:              list[str]
    load_bearing_offsets: list[int]   # absolute file offsets
    flagged_bytes_hex:    str         # space-separated "XX XX …"
    yara_rule:            str


@dataclass
class Report:
    """Top-level result returned by orchestrator.analyse()."""
    target_file:          str
    file_size:            int
    engine_version:       str
    signature_version:    str
    hits:                 list[Hit] = field(default_factory=list)
    patched_file:         Optional[str] = None
    clean_after_patching: bool = False
