"""OSINTMaster public information analysis."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("osintmaster")
except PackageNotFoundError:
    __version__ = "0+unknown"

__all__ = ["__version__"]
