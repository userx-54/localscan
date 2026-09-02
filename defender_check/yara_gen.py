"""
yara_gen.py — generate YARA rule sketches from flagged byte regions.

The key insight is using load-bearing byte data from sensitivity_analysis():
positions that are load-bearing keep their actual hex values, while every
other position becomes a '??' wildcard.  This produces a focused,
mutation-tolerant pattern that is much more useful than a raw hex blob.

Without sensitivity data (empty load_bearing list), the last 128 bytes of
the region are used verbatim as a fallback.
"""

import datetime
from typing import Optional


def generate_yara(
    index:         int,
    region_start:  int,
    flagged_bytes: bytes,
    strings:       list[str],
    sig_name:      Optional[str],
    load_bearing:  list[int],
) -> str:
    """
    Build a YARA rule sketch for one signature hit.

    Parameters
    ----------
    index         : hit index (0-based), used in the rule name
    region_start  : absolute file offset where flagged_bytes begins
    flagged_bytes : the raw bytes of the offending region
    strings       : printable strings extracted from the region
    sig_name      : Defender signature name, if available
    load_bearing  : absolute file offsets of load-bearing bytes
                    (from sensitivity_analysis); empty list = no data
    """
    hex_pattern = _build_hex_pattern(flagged_bytes, region_start, load_bearing)
    str_decls   = _build_string_decls(strings, hex_pattern)
    condition   = "any of ($str*) or $sig" if strings else "$sig"
    meta_desc   = _build_description(index, sig_name)

    lines = [
        f"rule DefenderCheck_Hit_{index} {{",
        "    meta:",
        f'        description = "{meta_desc}"',
        f'        date        = "{datetime.date.today()}"',
        "    strings:",
        *str_decls,
        "    condition:",
        f"        {condition}",
        "}",
    ]
    return "\n".join(lines)


# ── Private helpers ───────────────────────────────────────────────────────────
def _build_hex_pattern(
    flagged_bytes: bytes,
    region_start:  int,
    load_bearing:  list[int],
) -> str:
    """
    Build the hex pattern string for the $sig variable.

    With sensitivity data: load-bearing bytes keep their values; others → ??.
    Without sensitivity data: last 128 bytes verbatim (manageable rule size).
    """
    if load_bearing:
        lb_set = set(load_bearing)
        tokens = [
            f"{b:02x}" if (region_start + i) in lb_set else "??"
            for i, b in enumerate(flagged_bytes)
        ]
    else:
        tail   = flagged_bytes[-128:]
        tokens = [f"{b:02x}" for b in tail]

    return " ".join(tokens)


def _build_string_decls(strings: list[str], hex_pattern: str) -> list[str]:
    """
    Return the indented YARA strings-section lines.

    Up to 5 extracted strings are included as $str0 … $str4, followed by
    the $sig hex pattern.
    """
    decls: list[str] = []
    for j, s in enumerate(strings[:5]):
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        decls.append(f'        $str{j} = "{escaped}"')
    decls.append(f"        $sig = {{ {hex_pattern} }}")
    return decls


def _build_description(index: int, sig_name: Optional[str]) -> str:
    desc = f"DefenderCheck auto-generated — hit #{index}"
    if sig_name:
        desc += f" ({sig_name})"
    return desc
