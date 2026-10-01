"""Shared defaults and exit codes."""

from osintmaster import __version__

DEFAULT_TIMEOUT = 10.0
DEFAULT_CONCURRENCY = 5
DEFAULT_PER_HOST = 2
DEFAULT_HOST_INTERVAL = 1.0
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_INVALID = 2
EXIT_PARTIAL = 3
USER_AGENT = f"OSINTMaster/{__version__} (+https://github.com/Larslllllll/osintmaster)"
