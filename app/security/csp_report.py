"""CSP Violation Report endpoint — registered as a separate blueprint
so it can bypass CSRF protection (browser sends raw JSON, not a form)."""
from flask import Blueprint, request
from app import db, csrf
from app.models.security import CspReport

csp_report_bp = Blueprint("csp_report", __name__)


def _resolve_report_submission_id(session_id: int, document_uri: str | None, blocked_uri: str | None) -> str | None:
    """Map a CSP report back to the payload submission that produced it.

    Browser CSP reports do not include submission_id, so we resolve it by matching
    the report's object URL to SecurityLog rows in the same session.

    Strategy:
    1. Try to extract object_id from URI (for pages like /forum/192)
    2. If object_id available, match by object_type and object_id
    3. If object_id not available (like /forum/), use fallback: feature + session + latest submission
    """
    from app.utils.session_helper import resolve_csp_report_submission_ids
    from app.models.security import SecurityLog

    # Strategy 1: Try object_id-based resolution (for pages like /forum/192)
    candidates = resolve_csp_report_submission_ids(session_id, document_uri, blocked_uri)
    
    if len(candidates) == 1:
        return next(iter(candidates))
    
    # Strategy 2: Fallback to feature-based resolution (for pages like /forum/)
    # Normalize document_uri to feature
    if document_uri:
        from urllib.parse import urlparse
        parsed = urlparse(document_uri)
        normalized_path = parsed.path.strip("/") if parsed.path else "/"
        path_segments = normalized_path.split("/") if normalized_path else []
        resolved_feature = path_segments[0] if path_segments else None
        
        # Map URI path to source_feature
        feature_mapping = {
            "forum": "forum",
            "announcements": "announcement",
            "announcement": "announcement",
            "comments": "comment",
            "comment": "comment",
            "chat": "chat",
        }
        source_feature = feature_mapping.get(resolved_feature)
        
        if source_feature:
            # Query SecurityLog by session_id, source_feature, and submission_id is not NULL
            latest_log = (
                SecurityLog.query
                .filter_by(session_id=session_id, source_feature=source_feature)
                .filter(SecurityLog.submission_id.isnot(None))
                .order_by(SecurityLog.created_at.desc())
                .first()
            )
            
            if latest_log and latest_log.submission_id:
                return latest_log.submission_id
    
    # No candidate found
    return None


@csp_report_bp.route("/csp-report", methods=["POST"])
@csrf.exempt
def csp_report():
    data = request.get_json(silent=True, force=True) or {}
    report = data.get("csp-report", {})

    from app.utils.session_helper import get_active_session
    active_session = get_active_session()
    if not active_session:
        return "", 204

    document_uri = (report.get("document-uri", "") or "")[:500]
    blocked_uri = (report.get("blocked-uri", "") or "")[:500]
    submission_id = _resolve_report_submission_id(active_session.id, document_uri, blocked_uri)

    entry = CspReport(
        session_id=active_session.id,
        submission_id=submission_id,
        document_uri=document_uri,
        violated_directive=report.get("violated-directive", "")[:255],
        blocked_uri=blocked_uri,
        original_policy=report.get("original-policy", ""),
    )
    db.session.add(entry)
    db.session.commit()

    return "", 204
