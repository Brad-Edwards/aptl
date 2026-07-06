"""Version exposure in aptl/__init__.py."""

from __future__ import annotations


def test_version_is_populated() -> None:
    import aptl

    assert aptl.__version__
    assert aptl.__version__[0].isdigit()
