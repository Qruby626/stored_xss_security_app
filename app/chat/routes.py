import uuid
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.utils.decorators import can_modify_object, simulation_required, simulation_read_required
from app import db
from app.models.chat import ChatMessage
from app.utils.xss_detector import detect_xss

chat_bp = Blueprint("chat", __name__, template_folder="../../templates/chat")


@chat_bp.route("/", methods=["GET"])
@login_required
@simulation_read_required
def index():
    from app.utils.session_helper import get_active_session, get_viewed_session, build_session_filter
    from app.models.security import TestSession
    # READ operation: Use viewed session for historical access
    viewed_sess = get_viewed_session()
    active_sess = get_active_session()
    all_sessions = TestSession.query.filter_by(is_legacy=False).order_by(TestSession.started_at.desc()).all()

    messages = ChatMessage.query.filter(build_session_filter(ChatMessage, viewed_sess, context="read")).order_by(ChatMessage.created_at.asc()).limit(100).all()
    return render_template("chat/index.html", messages=messages, viewed_session=viewed_sess, active_session=active_sess, all_sessions=all_sessions)


@chat_bp.route("/", methods=["POST"])
@login_required
@simulation_required
def create_message():
    from app.utils.session_helper import get_active_session
    active_sess = get_active_session()

    if not active_sess:
        flash("Tidak ada session pengujian yang aktif. Silakan mulai session baru.", "warning")
        return redirect(url_for("chat.index"))

    message = request.form.get("message", "").strip()
    if not message:
        flash("Pesan tidak boleh kosong.", "warning")
        return redirect(url_for("chat.index"))

    try:
        submission_id = str(uuid.uuid4())
        log_message, _, _ = detect_xss(message, "chat", submission_id=submission_id)
        chat_msg = ChatMessage(message=message, user_id=current_user.id, session_id=active_sess.id)
        db.session.add(chat_msg)
        db.session.flush()
        if log_message:
            log_message.object_type = "chat_message"
            log_message.object_id = chat_msg.id
        db.session.commit()
        return redirect(url_for("chat.index"))
    except Exception:
        db.session.rollback()
        flash("Terjadi kesalahan saat mengirim pesan.", "danger")
        return redirect(url_for("chat.index"))


@chat_bp.route("/<int:message_id>/delete", methods=["POST"])
@login_required
@simulation_required
def delete(message_id):
    from app.utils.session_helper import get_active_session, build_session_filter
    active_sess = get_active_session()
    if not active_sess:
        flash("Tidak ada session pengujian yang aktif. Silakan mulai session baru.", "warning")
        return redirect(url_for("chat.index"))

    from app.models.security import SecurityLog

    # ─ Session Isolation Validation ────────────────────────────────────────────
    # Pastikan objek yang dihapus berasal dari session pengujian yang aktif,
    # bukan dari session lain. Mencegah unauthorized deletion antar skenario.
    msg = ChatMessage.query.filter(
        ChatMessage.id == message_id,
        build_session_filter(ChatMessage, active_sess, context="write")
    ).first()
    
    if msg is None:
        flash("Pesan chat tidak berada pada skenario pengujian yang sedang aktif.", "warning")
        return redirect(url_for("chat.index"))
    
    if not can_modify_object(msg):
        flash("Tidak diizinkan.", "danger")
    else:
        # Sinkronisasi penghapusan SecurityLog agar statistik Dashboard tetap konsisten.
        from app.utils.session_helper import sync_delete_security_log
        sync_delete_security_log(
            session_id=msg.session_id,
            source_feature="chat",
            payloads=[msg.message]
        )

        db.session.delete(msg)
        db.session.commit()
        flash("Pesan dihapus.", "info")
    return redirect(url_for("chat.index"))


@chat_bp.route("/<int:message_id>/edit", methods=["GET", "POST"])
@login_required
@simulation_required
def edit(message_id):
    from app.utils.session_helper import get_active_session, build_session_filter
    active_sess = get_active_session()
    
    if not active_sess:
        flash("Tidak ada session pengujian yang aktif.", "warning")
        return redirect(url_for("chat.index"))

    # ─ Session Isolation Validation ────────────────────────────────────────────
    # Pastikan objek yang diedit berasal dari session pengujian yang aktif,
    # bukan dari session lain. Mencegah unauthorized modification antar skenario.
    msg = ChatMessage.query.filter(
        ChatMessage.id == message_id,
        build_session_filter(ChatMessage, active_sess, context="write")
    ).first()
    
    if msg is None:
        flash("Pesan chat tidak berada pada skenario pengujian yang sedang aktif.", "warning")
        return redirect(url_for("chat.index"))
    
    if not can_modify_object(msg):
        flash("Tidak diizinkan.", "danger")
        return redirect(url_for("chat.index"))

    if request.method == "POST":
        message = request.form.get("message", "").strip()

        if not message:
            flash("Pesan wajib diisi.", "warning")
        else:
            try:
                submission_id = str(uuid.uuid4())
                # 1. XSS Detection first (create SecurityLog, add to session)
                log_message, _, _ = detect_xss(message, "chat", submission_id=submission_id)
                # 2. Update object
                msg.message = message
                # 3. Update SecurityLog with object_type and object_id
                if log_message:
                    log_message.object_type = "chat_message"
                    log_message.object_id = msg.id
                # 4. Single commit!
                db.session.commit()
                flash("Pesan berhasil diperbarui!", "success")
                return redirect(url_for("chat.index"))
            except Exception:
                db.session.rollback()
                flash("Terjadi kesalahan saat memperbarui pesan.", "danger")
                return redirect(url_for("chat.index"))

    return render_template("chat/edit.html", msg=msg)
