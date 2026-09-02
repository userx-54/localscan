"""Tests for the documented defender_check package surface."""


def test_documented_package_surface_exports_analyse():
    from defender_check import analyse

    assert analyse.__name__ == "analyse"
