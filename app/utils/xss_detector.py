"""XSS Rule-Based Detection Engine."""
import re
from typing import Tuple
from flask import current_app
from app import db
from app.models.security import SecurityLog


def detect_xss(
    payload: str,
    source_feature: str,
    submission_id: str | None = None,
    object_type: str | None = None,
    object_id: int | None = None
) -> Tuple[SecurityLog | None, str, str | None]:
    """
    Scan *payload* against all configured XSS patterns.

    Jika SecuritySetting.rule_detection_enabled = False, deteksi dilewati dan
    setiap input langsung dicatat sebagai "SAFE" (simulasi bypass detection).

    Returns:
        (security_log, status, matched_rule)  where security_log is the created
        SecurityLog object (or None if no active session), status is "DETECTED" or "SAFE".
    """
    # ─ Cek apakah Rule-Based Detection diaktifkan ─────────────────────────────
    try:
        from app.models.security import SecuritySetting
        settings = SecuritySetting.get_settings()
        detection_enabled = settings.rule_detection_enabled
    except Exception:
        detection_enabled = True  # fallback: always on

    matched_rule = None
    status = "SAFE"

    if detection_enabled:
        patterns = current_app.config.get("XSS_PATTERNS", [])
        for pattern in patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                status = "DETECTED"
                matched_rule = pattern
                break

    # Persist result (only when an active test session exists) ─────────────────
    from app.utils.session_helper import get_active_session
    active_sess = get_active_session()
    security_log = None
    if active_sess:
        security_log = SecurityLog(
            session_id=active_sess.id,
            source_feature=source_feature,
            payload=payload,
            matched_rule=matched_rule,
            status=status,
            submission_id=submission_id,
            object_type=object_type,
            object_id=object_id
        )
        db.session.add(security_log)

    return security_log, status, matched_rule
