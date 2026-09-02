"""
search.py — algorithms for locating flagged byte regions.

binary_search()      — finds the smallest prefix of a file that Defender flags.
sensitivity_analysis() — identifies which individual bytes within that region
                         are load-bearing for the signature.

Optional dependency: tqdm (pip install tqdm)
  - Used for progress bars; degrades silently to no bar if not installed.
"""

import math
from typing import Optional

from .models import ScanResult
from .scanner import scan

# ── Optional progress bars ────────────────────────────────────────────────────
try:
    from tqdm import tqdm
    _HAS_TQDM = True
except ImportError:
    _HAS_TQDM = False

# ── Constants ─────────────────────────────────────────────────────────────────
# Exported so orchestrator can use the same window size when slicing regions.
WINDOW = 256   # bytes to display / analyse around each hit


# ── Binary search ─────────────────────────────────────────────────────────────
def binary_search(
    data:      bytes,
    test_file: str,
    label:     str = "Scanning",
    debug:     bool = False,
) -> int:
    """
    Find the length of the smallest prefix of *data* that Defender flags.

    Invariant maintained throughout the loop:
        data[:lo]  — largest confirmed CLEAN prefix  (lo=0 means the empty file)
        data[:hi]  — smallest confirmed FLAGGED prefix

    When lo == hi the search has converged; the return value is that offset.

    On timeout or error MpCmdRun results, the midpoint is skipped upward to
    avoid stalling forever.  The total number of iterations is at most
    ceil(log2(len(data))), which is what the tqdm total is set to.
    """
    lo, hi      = 0, len(data)
    total_steps = math.ceil(math.log2(len(data))) if len(data) > 1 else 1

    bar = (
        tqdm(total=total_steps, desc=f"  {label}", unit="step", leave=False)
        if _HAS_TQDM else None
    )

    try:
        while lo < hi:
            mid = (lo + hi) // 2

            if debug:
                print(f"    [dbg] Testing {mid:,} bytes  (lo={lo}, hi={hi})")

            with open(test_file, "wb") as fh:
                fh.write(data[:mid])

            status, _ = scan(test_file)

            if status == ScanResult.THREAT:
                hi = mid
            elif status == ScanResult.NO_THREAT:
                lo = mid + 1
            else:
                # Timeout or error: skip upward to avoid an infinite loop.
                if debug:
                    print(f"    [dbg] Scan returned {status} at {mid} — skipping upward")
                lo = mid + 1

            if bar:
                bar.update(1)
    finally:
        if bar:
            bar.close()

    return lo


# ── Byte sensitivity analysis ─────────────────────────────────────────────────
def sensitivity_analysis(
    data:       bytes,
    bad_offset: int,
    test_file:  str,
    debug:      bool = False,
) -> list[int]:
    """
    Identify which bytes in the offending window are load-bearing.

    Each byte in data[max(0, bad_offset - WINDOW) : bad_offset] is flipped
    (XOR 0xFF) independently and the resulting prefix is re-scanned.  A byte
    is "load-bearing" if flipping it alone makes the file clean.

    Returns a list of absolute file offsets for all load-bearing bytes.

    Cost: at most WINDOW extra scans (256 by default).  Use --no-sensitivity
    on the CLI to skip this step when speed matters more than detail.
    """
    region_start = max(0, bad_offset - WINDOW)
    region_size  = bad_offset - region_start

    print(f"  Sensitivity: testing {region_size} bytes individually...")

    baseline     = bytearray(data[:bad_offset])
    load_bearing: list[int] = []

    positions = (
        tqdm(range(region_start, bad_offset), desc="  Sensitivity", unit="B", leave=False)
        if _HAS_TQDM
        else range(region_start, bad_offset)
    )

    for i in positions:
        probe    = bytearray(baseline)
        probe[i] ^= 0xFF                        # flip all 8 bits of this byte
        with open(test_file, "wb") as fh:
            fh.write(bytes(probe))
        status, _ = scan(test_file)
        if status == ScanResult.NO_THREAT:
            load_bearing.append(i)
            if debug:
                print(f"    [dbg] Load-bearing: 0x{i:X}  (value 0x{data[i]:02X})")

    return load_bearing
