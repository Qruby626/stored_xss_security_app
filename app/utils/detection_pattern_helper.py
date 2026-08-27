"""Helpers for Detection Pattern Management."""
from __future__ import annotations

from flask import current_app


def get_detection_patterns() -> list[str]:
    """
    Get the list of XSS detection patterns.

    Returns:
        List of regex patterns for XSS detection rules.
    """
    return current_app.config.get("XSS_PATTERNS", [])
