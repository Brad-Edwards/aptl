"""Advanced Purple Team Lab CLI."""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    # Version lives in pyproject.toml (managed by release-please); read it from
    # installed metadata so there is one source of truth.
    __version__ = _version("aptl")
except PackageNotFoundError:  # running from a source tree without installed metadata
    __version__ = "0.0.0"
