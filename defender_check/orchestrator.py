"""
orchestrator.py — full analysis pipeline.

analyse() is the single public entry point.  It:
  1. Reads version info and confirms the file is flagged.
  2. Loops: binary-search → per-hit analysis → patch → repeat.
  3. Writes the patched binary and YARA rule file when done.
"""

import os
import shutil
import tempfile
from typing import Optional

from .analysis import (
    _HAS_PEFILE,
    calc_entropy,
    entropy_note,
    extract_strings,
    hex_dump,
    pe_section_at,
)
from .models import Hit, Report, ScanResult
from .scanner import get_defender_info, scan
from .search import WINDOW, binary_search, sensitivity_analysis
from .yara_gen import generate_yara


def analyse(
    target_file:    str,
    debug:          bool = False,
    no_sensitivity: bool = False,
    quiet:          bool = False,
) -> Report:
    """
    Run the full DefenderCheck pipeline against *target_file*.

    Parameters
    ----------
    target_file    : path to the binary to analyse
    debug          : print binary-search progress each iteration
    no_sensitivity : skip per-byte sensitivity analysis (much faster)
    quiet          : suppress human-readable stdout (use when --json is active)

    Returns a fully-populated Report dataclass.
    """
    engine_ver, sig_ver = get_defender_info()

    with open(target_file, "rb") as fh:
        original = fh.read()

    report = Report(
        target_file=target_file,
        file_size=len(original),
        engine_version=engine_ver,
        signature_version=sig_ver,
    )

    def log(msg: str = "") -> None:
        if not quiet:
            print(msg)

    log(f"[*] Engine version   : {engine_ver}")
    log(f"[*] Signature version: {sig_ver}")
    log(f"[*] Target file size : {len(original):,} bytes")
    log()

    # Confirm the full file is actually flagged before spending time searching.
    status, _ = scan(target_file)
    if status == ScanResult.NO_THREAT:
        log("[+] No threat found in submitted file!")
        return report
    if status != ScanResult.THREAT:
        log(f"[-] Unexpected initial scan result: {status}")
        return report
    log("[*] Threat confirmed. Starting analysis...\n")

    tmpdir    = tempfile.mkdtemp(prefix="defcheck_")
    test_file = os.path.join(tmpdir, "testfile.exe")

    # Mutable working copy: each hit is zeroed out here to expose the next.
    working = bytearray(original)

    try:
        while True:
            hit_idx = len(report.hits)
            log(f"── Hit #{hit_idx + 1} {'─' * 48}")

            bad_offset = binary_search(
                bytes(working), test_file,
                label=f"Hit #{hit_idx + 1}",
                debug=debug,
            )

            if bad_offset == 0:
                log("[+] No more signatures found.")
                break

            # Re-scan the converged slice to pull the signature name.
            with open(test_file, "wb") as fh:
                fh.write(bytes(working[:bad_offset]))
            _, sig_name = scan(test_file, get_sig=True)

            # ── Per-hit analysis ──────────────────────────────────────────
            region_start  = max(0, bad_offset - WINDOW)
            flagged_bytes = bytes(working[region_start:bad_offset])
            ent           = calc_entropy(flagged_bytes)
            ent_note      = entropy_note(ent)
            strs          = extract_strings(flagged_bytes)
            section       = pe_section_at(bytes(original), bad_offset)

            load_bearing = (
                []
                if no_sensitivity
                else sensitivity_analysis(bytes(working), bad_offset, test_file, debug)
            )

            yara = generate_yara(
                hit_idx, region_start, flagged_bytes, strs, sig_name, load_bearing
            )

            hit = Hit(
                index=hit_idx,
                offset=bad_offset,
                offset_hex=f"0x{bad_offset:X}",
                signature=sig_name,
                pe_section=section,
                entropy=round(ent, 4),
                entropy_note=ent_note,
                strings=strs,
                load_bearing_offsets=load_bearing,
                flagged_bytes_hex=" ".join(f"{b:02X}" for b in flagged_bytes),
                yara_rule=yara,
            )
            report.hits.append(hit)

            # ── Console output ────────────────────────────────────────────
            _print_hit(hit, ent, ent_note, strs, load_bearing, no_sensitivity,
                       flagged_bytes, yara, quiet, log)

            # ── Patch and continue ────────────────────────────────────────
            _patch_working(working, load_bearing, region_start, bad_offset,
                           test_file, log)

            # Full-file check: stop if clean, loop if more hits remain.
            with open(test_file, "wb") as fh:
                fh.write(bytes(working))
            post_status, _ = scan(test_file)
            if post_status == ScanResult.NO_THREAT:
                log("[+] File is clean after patching this hit.\n")
                break
            if post_status != ScanResult.THREAT:
                log(f"[!] Post-patch scan returned {post_status}. Stopping.\n")
                break

    except KeyboardInterrupt:
        log("\n[!] Interrupted by user.")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    _write_outputs(report, working, target_file, log)
    return report


# ── Private helpers ───────────────────────────────────────────────────────────
def _print_hit(
    hit:            Hit,
    ent:            float,
    ent_note:       str,
    strs:           list[str],
    load_bearing:   list[int],
    no_sensitivity: bool,
    flagged_bytes:  bytes,
    yara:           str,
    quiet:          bool,
    log,
) -> None:
    """Print the human-readable summary for one hit."""
    log(f"[!] Offset        : {hit.offset_hex}  ({hit.offset:,} bytes into file)")
    if hit.signature:
        log(f"    Signature     : {hit.signature}")
    if hit.pe_section is not None:
        log(f"    PE section    : {hit.pe_section}")
    elif not _HAS_PEFILE:
        log("    PE section    : (install pefile to enable)")
    log(f"    Entropy       : {ent:.4f} bits/byte  — {ent_note}")
    if strs:
        preview = strs[:5]
        more    = f"  (+{len(strs) - 5} more)" if len(strs) > 5 else ""
        log(f"    Strings       : {preview}{more}")
    if load_bearing:
        lb_hex = [f"0x{o:X}" for o in load_bearing[:10]]
        more   = f"  (+{len(load_bearing) - 10} more)" if len(load_bearing) > 10 else ""
        log(f"    Load-bearing  : {lb_hex}{more}")
    elif not no_sensitivity:
        log("    Load-bearing  : none found (signature may span all bytes equally)")
    log()
    log("    Offending region hex dump:")
    if not quiet:
        hex_dump(flagged_bytes)
    log()
    log("    YARA rule sketch:")
    if not quiet:
        for line in yara.splitlines():
            log(f"    {line}")
    log()


def _patch_working(
    working:      bytearray,
    load_bearing: list[int],
    region_start: int,
    bad_offset:   int,
    test_file:    str,
    log,
) -> None:
    """
    Zero out the flagged region in *working* so the next search finds fresh hits.

    Tries a surgical patch (only load-bearing bytes) first.  If Defender still
    flags the result, falls back to zeroing the entire window.
    """
    if load_bearing:
        for i in load_bearing:
            working[i] = 0x00
        # Verify the surgical patch is sufficient.
        with open(test_file, "wb") as fh:
            fh.write(bytes(working))
        patch_status, _ = scan(test_file)
        if patch_status == ScanResult.THREAT:
            log("    [!] Surgical patch insufficient — zeroing full window.")
            for i in range(region_start, bad_offset):
                working[i] = 0x00
    else:
        for i in range(region_start, bad_offset):
            working[i] = 0x00


def _write_outputs(
    report:      Report,
    working:     bytearray,
    target_file: str,
    log,
) -> None:
    """Write the patched binary and YARA rule file; update report in-place."""
    if not report.hits:
        return

    base, ext    = os.path.splitext(target_file)
    patched_path = f"{base}_patched{ext}"
    yara_path    = f"{base}_signatures.yar"

    with open(patched_path, "wb") as fh:
        fh.write(bytes(working))

    final_status, _ = scan(patched_path)
    report.patched_file         = patched_path
    report.clean_after_patching = (final_status == ScanResult.NO_THREAT)

    with open(yara_path, "w") as fh:
        fh.write("\n\n".join(h.yara_rule for h in report.hits))

    clean_icon = "CLEAN ✓" if report.clean_after_patching else "STILL FLAGGED ✗"
    log(f"[*] Patched binary → {patched_path}  [{clean_icon}]")
    log(f"[*] YARA rules     → {yara_path}")
    log()
