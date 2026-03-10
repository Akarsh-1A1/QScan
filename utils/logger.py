"""
QScan - Centralized Logging Utility
"""

import logging
import sys
from typing import Optional

# Global logger registry
_loggers = {}
_configured = False


def setup_logger(level: str = "INFO", log_file: Optional[str] = None):
    """Configure the root QScan logger."""
    global _configured
    if _configured:
        return

    root = logging.getLogger("qscan")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Console handler with colored output
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(getattr(logging, level.upper(), logging.INFO))

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s",
        datefmt="%H:%M:%S",
    )
    console.setFormatter(fmt)
    root.addHandler(console)

    # File handler (optional)
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        ))
        root.addHandler(fh)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Get a named child logger under the qscan namespace."""
    if name not in _loggers:
        logger = logging.getLogger(f"qscan.{name}")
        _loggers[name] = logger
    return _loggers[name]
