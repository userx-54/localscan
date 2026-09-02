"""
cli.py — command-line interface.

Handles argument parsing, locates MpCmdRun.exe, runs the pipeline,
and formats the final output (human-readable or JSON).

Entry point: main()  (also invoked by __main__.py for `python -m defender_check`)
"""

import argparse
import json
import os
import sys
from dataclasses import asdict

from .orchestrator import analyse
from .scanner import configure, locate_mpcmdrun


def main() -> None:
    args = _parse_args()

    if not os.path.isfile(args.file):
        print(f"[-] File not found: {args.file}")
        sys.exit(1)

    # Resolve and register MpCmdRun.exe path before any scan() call.
    try:
        mpcmdrun_path = locate_mpcmdrun()
    except FileNotFoundError as e:
        print(f"[-] {e}")
        sys.exit(1)

    configure(mpcmdrun_path)

    if not args.json:
        print(f"[*] MpCmdRun.exe   : {mpcmdrun_path}\n")

    report = analyse(
        target_file=args.file,
        debug=args.debug,
        no_sensitivity=args.no_sensitivity,
        quiet=args.json,
    )

    if args.json:
        print(json.dumps(asdict(report), indent=2))
    else:
        _print_summary(report)


# ── Private helpers ───────────────────────────────────────────────────────────
def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DefenderCheck — locate and analyse every byte Windows Defender flags.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m defender_check payload.exe\n"
            "  python -m defender_check payload.exe --no-sensitivity\n"
            "  python -m defender_check payload.exe --json > report.json\n"
            "  python -m defender_check payload.exe --debug\n"
        ),
    )
    parser.add_argument(
        "file",
        help="Binary to analyse",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print binary-search progress each iteration",
    )
    parser.add_argument(
        "--no-sensitivity",
        action="store_true",
        help="Skip per-byte sensitivity analysis (much faster, less detail)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON report to stdout (suppresses human-readable output)",
    )
    return parser.parse_args()


def _print_summary(report) -> None:
    print("═" * 60)
    print(f"  Signatures found      : {len(report.hits)}")
    if report.patched_file:
        icon = "✓ clean" if report.clean_after_patching else "✗ still flagged"
        print(f"  Patched file          : {report.patched_file}  [{icon}]")
    print("═" * 60)
