"""Advanced Purple Team Lab CLI."""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    __version__ = _version("aptl")
except PackageNotFoundError:  # running from a source tree without installed metadata
    __version__ = "0.0.0"
