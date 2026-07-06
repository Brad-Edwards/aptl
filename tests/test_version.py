"""Version resolution in aptl/__init__.py."""

from __future__ import annotations

import importlib
import importlib.metadata as _md

import pytest


def test_version_resolves_from_installed_metadata() -> None:
    import aptl

    assert aptl.__version__
    assert aptl.__version__ != "0.0.0"


def test_version_falls_back_when_not_installed() -> None:
    import aptl

    with pytest.MonkeyPatch.context() as mp:
        def _raise(name: str) -> str:
            raise _md.PackageNotFoundError(name)

        mp.setattr(_md, "version", _raise)
        importlib.reload(aptl)
        assert aptl.__version__ == "0.0.0"

    # Restore the real version for the rest of the suite.
    importlib.reload(aptl)
