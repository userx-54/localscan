"""
analysis.py — static analysis of byte regions.

All functions are pure (no I/O, no Defender calls) and operate only on
the bytes passed to them.  They can be used independently of the rest of
the package.

Optional dependency: pefile (pip install pefile)
  - Required only for pe_section_at(); all other functions work without it.
"""

import math
import re
from collections import Counter
from typing import Optional

# ── Optional PE parsing ───────────────────────────────────────────────────────
try:
    import pefile
    _HAS_PEFILE = True
except ImportError:
    _HAS_PEFILE = False

# ── Constants ─────────────────────────────────────────────────────────────────
_MIN_STR_LEN = 4   # minimum printable-char run counted as a string

_ASCII_RE = re.compile(rb"[\x20-\x7E]{4,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7E]\x00){4,}")


# ── Entropy ───────────────────────────────────────────────────────────────────
def calc_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 – 8.0)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def entropy_note(e: float) -> str:
    """Human-readable interpretation of an entropy value."""
    if e > 7.0:
        return "high — likely encrypted or compressed data"
    if e > 5.0:
        return "medium — mixed content"
    if e < 3.0:
        return "low — likely plaintext strings or structured data"
    return "moderate"


# ── String extraction ─────────────────────────────────────────────────────────
def extract_strings(data: bytes) -> list[str]:
    """
    Return all printable ASCII and UTF-16LE strings of length >= _MIN_STR_LEN
    found in *data*.
    """
    results: list[str] = []

    for m in _ASCII_RE.finditer(data):
        s = m.group().decode("ascii")
        if len(s) >= _MIN_STR_LEN:
            results.append(s)

    for m in _UTF16_RE.finditer(data):
        try:
            s = m.group().decode("utf-16-le")
            if len(s) >= _MIN_STR_LEN:
                results.append(s)
        except UnicodeDecodeError:
            pass

    return results


# ── PE section mapping ────────────────────────────────────────────────────────
def pe_section_at(data: bytes, offset: int) -> Optional[str]:
    """
    Return the name of the PE section that contains *offset* (raw file offset).

    Returns None for non-PE files so callers can treat it as "N/A" without
    special-casing.  Returns "(outside all sections)" if the offset is in the
    file but not covered by any section (e.g. the PE header itself).

    Requires pefile; returns None silently if it is not installed.
    """
    if not _HAS_PEFILE:
        return None
    try:
        pe = pefile.PE(data=data, fast_load=True)
        for s in pe.sections:
            start = s.PointerToRawData
            end   = start + s.SizeOfRawData
            if start <= offset < end:
                return s.Name.decode("utf-8", errors="replace").rstrip("\x00")
        return "(outside all sections)"
    except pefile.PEFormatError:
        return None   # not a PE file — caller treats None as "N/A"


# ── Hex dump ──────────────────────────────────────────────────────────────────
def hex_dump(data: bytes, cols: int = 16, indent: int = 4) -> None:
    """Print a classic offset / hex / ASCII dump to stdout."""
    pad = " " * indent
    for i in range(0, len(data), cols):
        chunk    = data[i : i + cols]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        asc_part = "".join(chr(b) if 0x20 <= b < 0x7F else "·" for b in chunk)
        print(f"{pad}{i:08X}   {hex_part:<{cols * 3 - 1}}   {asc_part}")
