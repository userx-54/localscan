"""
conftest.py — pytest configuration and shared fixtures.

Adds the project root to sys.path so that `import defender_check` works
regardless of which directory pytest is invoked from.
"""

import os
import sys
import types
from unittest.mock import MagicMock

import pytest

# Ensure the package is importable when tests are run from any directory.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Shared fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def tmp_exe(tmp_path):
    """A small temporary binary file for use as a scan target."""
    p = tmp_path / "target.exe"
    p.write_bytes(b"\x00" * 64)
    return p


@pytest.fixture
def mock_winreg():
    """
    A fake winreg module that can be patched into defender_check.scanner.

    Tests that exercise the Windows-registry code path use this fixture so they
    run on Linux/macOS as well as Windows.
    """
    mod = types.ModuleType("winreg")
    mod.HKEY_LOCAL_MACHINE = "HKEY_LOCAL_MACHINE"
    mod.OpenKey             = MagicMock()
    mod.QueryValueEx        = MagicMock()
    mod.CloseKey            = MagicMock()
    return mod
