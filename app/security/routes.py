from datetime import datetime

from flask import Blueprint, render_template, jsonify, request, redirect, url_for, flash, current_app
# pyrefly: ignore [missing-import]
from flask_login import login_required
from app.utils.decorators import admin_required
from sqlalchemy import func
from app import db
from app.models.security import SecurityLog, CspReport, SecuritySetting, StolenCookie, TestSession
from app.utils.session_helper import (
    get_active_session,
    resolve_session_id,
    get_session_stats,
    get_session_history_rows,
    chart_data_for_session,
)
from sqlalchemy.exc import OperationalError

security_bp = Blueprint("security", __name__, template_folder="../../templates/security")

# Expose Python built-ins to Jinja2
@security_bp.app_template_global()
def _enumerate(iterable):
    """Make Python's enumerate() available in Jinja2 templates."""
    return enumerate(iterable)


def _session_redirect(endpoint: str, session_id: int | None = None, **kwargs):
    """Redirect preserving session_id from querystring or form values.

    This supports preserving the selected session when actions are performed via POST
    (session_id may be submitted as a hidden form field) as well as via GET.
    """
    sid = session_id if session_id is not None else request.values.get("session_id")
    if sid:
        kwargs["session_id"] = sid
    return redirect(url_for(endpoint, **kwargs))


# ── Dashboard ──────────────────────────────────────────────────────────────────
@security_bp.route("/dashboard")
@login_required
@admin_required
def dashboard():
    sessions = (
        TestSession.query
        .filter_by(is_legacy=False)
        .order_by(TestSession.started_at.desc())
        .all()
    )
    active_session = get_active_session()
    selected_session_id = resolve_session_id()
    selected_session = TestSession.query.get(selected_session_id) if selected_session_id else None

    if selected_session_id:
        stats = get_session_stats(selected_session_id)
        feature_summary = chart_data_for_session(selected_session_id)
    else:
        stats = {
            "total_objects": 0,
            "total_tested": 0,
            "total_detected": 0,
            "total_safe": 0,
            "total_csp": 0,
            "total_blocked": 0,
            "detection_rate": 0,
            "blocking_rate": 0,
        }
        feature_summary = {}

    settings = SecuritySetting.get_settings()
    stolen_cookies = StolenCookie.query.order_by(StolenCookie.created_at.desc()).limit(50).all()

    return render_template(
        "security/dashboard.html",
        sessions=sessions,
        active_session=active_session,
        selected_session=selected_session,
        selected_session_id=selected_session_id,
        settings=settings,
        stolen_cookies=stolen_cookies,
        feature_summary=feature_summary,
        **stats,
    )


# ── Detection Logs ─────────────────────────────────────────────────────────────
@security_bp.route("/logs")
@login_required
@admin_required
def logs():
    status_filter = request.args.get("status", "").strip()
    feature_filter = request.args.get("feature", "").strip()
    search_query = request.args.get("search", "").strip()
    page = request.args.get("page", 1, type=int)
    selected_session_id = resolve_session_id()
    selected_session = TestSession.query.get(selected_session_id) if selected_session_id else None
    active_session = get_active_session()

    sessions = (
        TestSession.query
        .filter_by(is_legacy=False)
        .order_by(TestSession.started_at.desc())
        .all()
    )
    query = SecurityLog.query

    if selected_session_id:
        query = query.filter(SecurityLog.session_id == selected_session_id)
    else:
        query = query.filter(SecurityLog.id == -1)

    if status_filter:
        query = query.filter(SecurityLog.status == status_filter)
    if feature_filter:
        query = query.filter(SecurityLog.source_feature == feature_filter)
    if search_query:
        query = query.filter(SecurityLog.payload.like(f"%{search_query}%"))

    pagination = query.order_by(SecurityLog.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    return render_template(
        "security/logs.html",
        logs=pagination.items,
        pagination=pagination,
        status_filter=status_filter,
        feature_filter=feature_filter,
        search_query=search_query,
        sessions=sessions,
        selected_session=selected_session,
        selected_session_id=selected_session_id,
        active_session=active_session,
    )


# ── CSP Reports ────────────────────────────────────────────────────────────────
@security_bp.route("/reports")
@login_required
@admin_required
def reports():
    selected_session_id = resolve_session_id()
    selected_session = TestSession.query.get(selected_session_id) if selected_session_id else None
    active_session = get_active_session()
    sessions = (
        TestSession.query
        .filter_by(is_legacy=False)
        .order_by(TestSession.started_at.desc())
        .all()
    )

    query = CspReport.query
    if selected_session_id:
        query = query.filter(CspReport.session_id == selected_session_id)
    else:
        query = query.filter(CspReport.id == -1)

    try:
        # Ambil seluruh data session aktif tanpa limit
        all_reports = query.order_by(CspReport.created_at.desc()).all()
        
        # Deduplikasi berdasarkan submission_id di level Python
        # Untuk setiap submission, gunakan report terbaru sebagai representasi
        # Hanya masukkan submission_id yang masih valid (masih ada di SecurityLog pada session yang sama)
        seen_submission_ids = set()
        reports_list = []
        for report in all_reports:
            if report.submission_id and report.submission_id not in seen_submission_ids:
                # Validasi: submission_id harus masih ada di SecurityLog pada session yang sama
                if SecurityLog.query.filter_by(
                    session_id=selected_session_id,
                    submission_id=report.submission_id
                ).first():
                    seen_submission_ids.add(report.submission_id)
                    reports_list.append(report)
        
        total_csp_reports = len(reports_list)
        max_reports = total_csp_reports
    except OperationalError as exc:
        # Likely the DB schema/migration wasn't applied; show instructive message instead of 500
        flash(
            "Database schema mismatch detected: kolom `csp_reports.session_id` tidak ditemukan. "
            "Jalankan migrasi non-destruktif di `sql/migration_add_test_sessions_safe.sql` atau "
            "jalankan `alembic upgrade head` untuk memperbarui skema.",
            "danger",
        )
        reports_list = []
        total_csp_reports = 0
        max_reports = 0
    return render_template(
        "security/reports.html",
        reports=reports_list,
        total_csp_reports=total_csp_reports,
        max_reports=max_reports,
        sessions=sessions,
        selected_session=selected_session,
        selected_session_id=selected_session_id,
        active_session=active_session,
    )


# ── Test Sessions History ──────────────────────────────────────────────────────
@security_bp.route("/sessions")
@login_required
@admin_required
def sessions():
    history = get_session_history_rows()
    return render_template("security/sessions.html", history=history)


# ── Start Test Session ─────────────────────────────────────────────────────────
@security_bp.route("/sessions/start", methods=["POST"])
@login_required
@admin_required
def start_session():
    if get_active_session():
        flash("Masih ada skenario pengujian aktif. Akhiri skenario terlebih dahulu.", "warning")
        return redirect(url_for("security.dashboard"))

    session_name = request.form.get("session_name", "").strip()
    description = request.form.get("description", "").strip()

    if not session_name:
        flash("Nama skenario wajib diisi.", "danger")
        return redirect(url_for("security.dashboard"))

    # Reset simulation academic data is no longer needed here as query views filter by active session automatically.

    session = TestSession(
        session_name=session_name,
        description=description or None,
        started_at=datetime.now(),
        status="active",
    )
    db.session.add(session)
    db.session.commit()

    # Perbaikan: Simpan session_id baru ke Flask Session secara langsung agar
    # viewed_session_id otomatis mengarah ke sesi baru di seluruh aplikasi.
    from flask import session as flask_session
    flask_session["viewed_session_id"] = session.id

    flash(
        'Skenario pengujian berhasil dibuat. Data simulasi akademik telah dikosongkan dan sesi pengujian baru telah diaktifkan.',
        "success",
    )
    return redirect(url_for("security.dashboard", session_id=session.id))


# ── End Test Session ───────────────────────────────────────────────────────────
@security_bp.route("/sessions/end", methods=["POST"])
@login_required
@admin_required
def end_session():
    active = get_active_session()
    if not active:
        flash("Belum ada skenario pengujian aktif untuk diakhiri.", "warning")
        return redirect(url_for("security.dashboard"))

    active.ended_at = datetime.now()
    active.status = "finished"
    db.session.commit()

    flash(f'Skenario pengujian "{active.session_name}" selesai. Data tetap tersimpan.', "success")
    return redirect(url_for("security.dashboard"))
# ── Delete Test Session (and related logs/reports) -------------------------
@security_bp.route("/sessions/delete", methods=["POST"])
@login_required
@admin_required
def delete_session():
    try:
        sid = int(request.form.get("session_id") or 0)
    except (TypeError, ValueError):
        flash("Skenario tidak valid.", "danger")
        return redirect(url_for("security.dashboard"))

    session = TestSession.query.get(sid)
    if not session:
        flash("Skenario tidak ditemukan atau sudah dihapus.", "warning")
        return redirect(url_for("security.dashboard"))

    # Rely on ORM-level cascade configured in TestSession model
    db.session.delete(session)
    db.session.commit()

    flash(f'Skenario pengujian "{session.session_name}" dan data terkait telah dihapus.', "success")

    # If other sessions remain, redirect to the most recent (by started_at) so UI selects it;
    # otherwise redirect to dashboard with no session selected (placeholder shown).
    next_session = (
        TestSession.query
        .filter(TestSession.id != sid)
        .filter_by(is_legacy=False)
        .order_by(TestSession.started_at.desc())
        .first()
    )
    if next_session:
        return redirect(url_for("security.dashboard", session_id=next_session.id))
    return redirect(url_for("security.dashboard"))


# ── Rules ──────────────────────────────────────────────────────────────────────
from app.utils.detection_pattern_helper import get_detection_patterns

@security_bp.route("/rules")
@login_required
@admin_required
def rules():
    patterns = get_detection_patterns()
    return render_template("security/rules.html", patterns=patterns)


# ── Statistics ─────────────────────────────────────────────────────────────────
@security_bp.route("/statistics")
@login_required
@admin_required
def statistics():
    selected_session_id = resolve_session_id()
    selected_session = TestSession.query.get(selected_session_id) if selected_session_id else None
    active_session = get_active_session()
    sessions = (
        TestSession.query
        .filter_by(is_legacy=False)
        .order_by(TestSession.started_at.desc())
        .all()
    )

    # Compute stats for selected session
    if selected_session_id:
        stats = get_session_stats(selected_session_id)
    else:
        stats = {
            "total_objects": 0,
            "total_tested": 0,
            "total_detected": 0,
            "total_safe": 0,
            "total_csp": 0,
            "total_blocked": 0,
            "detection_rate": 0,
            "blocking_rate": 0,
        }

    # Compute metrics for all sessions (for the comparison table) without nested stats objects
    sessions_with_stats = []
    for s in sessions:
        s_stats = get_session_stats(s.id)
        sessions_with_stats.append({
            "session": s,
            "total_objects": s_stats["total_objects"],
            "total_tested": s_stats["total_tested"],
            "total_detected": s_stats["total_detected"],
            "total_blocked": s_stats["total_blocked"],
            "detection_rate": s_stats["detection_rate"],
            "blocking_rate": s_stats["blocking_rate"],
        })

    if selected_session_id:
        by_feature = (
            db.session.query(
                SecurityLog.source_feature, SecurityLog.status, func.count(SecurityLog.id)
            )
            .filter(SecurityLog.session_id == selected_session_id)
            .group_by(SecurityLog.source_feature, SecurityLog.status)
            .all()
        )
    else:
        by_feature = []

    return render_template(
        "security/statistics.html",
        by_feature=by_feature,
        sessions=sessions,
        sessions_with_stats=sessions_with_stats,
        selected_session=selected_session,
        selected_session_id=selected_session_id,
        active_session=active_session,
        **stats,
    )


# ── Statistics API (JSON) ──────────────────────────────────────────────────────
@security_bp.route("/api/chart-data")
@login_required
@admin_required
def chart_data():
    selected_session_id = resolve_session_id()
    if not selected_session_id:
        return jsonify({})
    return jsonify(chart_data_for_session(selected_session_id))


# ── Security Toggle ────────────────────────────────────────────────────────────
@security_bp.route("/toggle", methods=["POST"])
@login_required
@admin_required
def toggle():
    toggle_name = request.form.get("toggle_name", "")
    toggle_value = request.form.get("toggle_value", "1") == "1"

    settings = SecuritySetting.get_settings()

    if toggle_name == "rule_detection":
        settings.rule_detection_enabled = toggle_value
        label = "Rule-Based Detection"
    elif toggle_name == "csp_nonce":
        settings.csp_nonce_enabled = toggle_value
        label = "CSP Nonce"
    else:
        flash("Parameter toggle tidak valid.", "danger")
        return _session_redirect("security.dashboard")

    db.session.commit()
    status_text = "DIAKTIFKAN ✅" if toggle_value else "DINONAKTIFKAN ⚠️"
    flash(f"{label} berhasil {status_text}.", "success" if toggle_value else "warning")
    return _session_redirect("security.dashboard")
