import uuid
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models.announcement import Announcement
from app.utils.xss_detector import detect_xss
from app.utils.decorators import can_modify_object, simulation_required, simulation_read_required
from app.utils.session_helper import get_active_session, get_viewed_session, build_session_filter

announcements_bp = Blueprint("announcements", __name__, template_folder="../../templates/announcements")


@announcements_bp.route("/")
@login_required
@simulation_read_required
def index():
    # READ operation: Use viewed session for historical access
    viewed_sess = get_viewed_session()
    active_sess = get_active_session()
    from app.models.security import TestSession
    all_sessions = TestSession.query.filter_by(is_legacy=False).order_by(TestSession.started_at.desc()).all()
    items = Announcement.query.filter(build_session_filter(Announcement, viewed_sess, context="read")).order_by(Announcement.created_at.desc()).all()
    can_modify = active_sess is not None
    return render_template("announcements/index.html", items=items, can_modify=can_modify, viewed_session=viewed_sess, active_session=active_sess, all_sessions=all_sessions)


@announcements_bp.route("/create", methods=["GET", "POST"])
@login_required
@simulation_required
def create():
    active_sess = get_active_session()
    
    if not active_sess:
        flash("Tidak ada session pengujian yang aktif. Silakan mulai session baru.", "warning")
        return redirect(url_for("announcements.index"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()

        if not title or not content:
            flash("Judul dan konten wajib diisi.", "warning")
        else:
            try:
                submission_id = str(uuid.uuid4())
                # 1. XSS Detection first (create SecurityLog, add to session)
                log_title, _, _ = detect_xss(title, "announcement", submission_id=submission_id)
                log_content, _, _ = detect_xss(content, "announcement", submission_id=submission_id)
                # 2. Create object and add to session
                ann = Announcement(title=title, content=content, user_id=current_user.id, session_id=active_sess.id)
                db.session.add(ann)
                # 3. Flush to get object.id without committing
                db.session.flush()
                # 4. Update SecurityLogs with object_type and object_id
                if log_title:
                    log_title.object_type = "announcement"
                    log_title.object_id = ann.id
                if log_content:
                    log_content.object_type = "announcement"
                    log_content.object_id = ann.id
                # 5. Single commit!
                db.session.commit()
                flash("Pengumuman berhasil dibuat!", "success")
                return redirect(url_for("announcements.index"))
            except Exception:
                db.session.rollback()
                flash("Terjadi kesalahan saat membuat pengumuman.", "danger")
                return redirect(url_for("announcements.index"))

    return render_template("announcements/create.html")


@announcements_bp.route("/<int:ann_id>")
@login_required
@simulation_read_required
def detail(ann_id):
    # READ operation: Use viewed session for historical access
    viewed_sess = get_viewed_session()
    active_sess = get_active_session()
    from app.models.security import TestSession
    all_sessions = TestSession.query.filter_by(is_legacy=False).order_by(TestSession.started_at.desc()).all()
    
    announcement = Announcement.query.filter(
        Announcement.id == ann_id,
        build_session_filter(Announcement, viewed_sess, context="read")
    ).first_or_404()
    can_modify_announcement = can_modify_object(announcement) and active_sess is not None
    return render_template("announcements/detail.html", announcement=announcement, can_modify=active_sess is not None, can_modify_announcement=can_modify_announcement, viewed_session=viewed_sess, active_session=active_sess, all_sessions=all_sessions)


@announcements_bp.route("/<int:ann_id>/delete", methods=["POST"])
@login_required
@simulation_required
def delete(ann_id):
    active_sess = get_active_session()
    if not active_sess:
        flash("Tidak ada session pengujian yang aktif. Silakan mulai session baru.", "warning")
        return redirect(url_for("announcements.index"))

    # ─ Session Isolation Validation ────────────────────────────────────────────
    # Pastikan objek yang dihapus berasal dari session pengujian yang aktif,
    # bukan dari session lain. Mencegah unauthorized deletion antar skenario.
    ann = Announcement.query.filter(
        Announcement.id == ann_id,
        build_session_filter(Announcement, active_sess, context="write")
    ).first()
    
    if ann is None:
        flash("Pengumuman tidak berada pada skenario pengujian yang sedang aktif.", "warning")
        return redirect(url_for("announcements.index"))

    # ─ Ownership-Based Authorization (Backend Validation)
    if not can_modify_object(ann):
        flash("Anda tidak memiliki hak untuk melakukan aksi tersebut.", "danger")
        return redirect(url_for("announcements.detail", ann_id=ann.id))

    # Sinkronisasi penghapusan SecurityLog agar statistik Dashboard tetap konsisten.
    from app.utils.session_helper import sync_delete_security_log
    sync_delete_security_log(
        session_id=ann.session_id,
        source_feature="announcement",
        payloads=[ann.title, ann.content]
    )

    db.session.delete(ann)
    db.session.commit()
    flash("Pengumuman dihapus.", "info")
    return redirect(url_for("announcements.index"))


@announcements_bp.route("/<int:ann_id>/edit", methods=["GET", "POST"])
@login_required
@simulation_required
def edit(ann_id):
    active_sess = get_active_session()
    
    if not active_sess:
        flash("Tidak ada session pengujian yang aktif.", "warning")
        return redirect(url_for("announcements.index"))

    # ─ Session Isolation Validation ────────────────────────────────────────────
    # Pastikan objek yang diedit berasal dari session pengujian yang aktif,
    # bukan dari session lain. Mencegah unauthorized modification antar skenario.
    ann = Announcement.query.filter(
        Announcement.id == ann_id,
        build_session_filter(Announcement, active_sess, context="write")
    ).first()
    
    if ann is None:
        flash("Pengumuman tidak berada pada skenario pengujian yang sedang aktif.", "warning")
        return redirect(url_for("announcements.index"))

    # ─ Ownership-Based Authorization (Backend Validation)
    if not can_modify_object(ann):
        flash("Anda tidak memiliki hak untuk melakukan aksi tersebut.", "danger")
        return redirect(url_for("announcements.detail", ann_id=ann.id))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()

        if not title or not content:
            flash("Judul dan konten wajib diisi.", "warning")
        else:
            try:
                submission_id = str(uuid.uuid4())
                # 1. XSS Detection first (create SecurityLog, add to session)
                log_title, _, _ = detect_xss(title, "announcement", submission_id=submission_id)
                log_content, _, _ = detect_xss(content, "announcement", submission_id=submission_id)
                # 2. Update object
                ann.title = title
                ann.content = content
                # 3. Update SecurityLogs with object_type and object_id
                if log_title:
                    log_title.object_type = "announcement"
                    log_title.object_id = ann.id
                if log_content:
                    log_content.object_type = "announcement"
                    log_content.object_id = ann.id
                # 4. Single commit!
                db.session.commit()
                flash("Pengumuman berhasil diperbarui!", "success")
                return redirect(url_for("announcements.index"))
            except Exception:
                db.session.rollback()
                flash("Terjadi kesalahan saat memperbarui pengumuman.", "danger")
                return redirect(url_for("announcements.index"))

    return render_template("announcements/edit.html", announcement=ann)
