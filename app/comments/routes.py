import uuid
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models.comment import Comment
from app.models.forum import ForumPost
from app.utils.xss_detector import detect_xss
from app.utils.decorators import can_modify_object, simulation_required, simulation_read_required
from app.utils.session_helper import get_active_session, get_viewed_session, build_session_filter

comments_bp = Blueprint("comments", __name__, template_folder="../../templates/comments")

@comments_bp.route("/post/<int:post_id>", methods=["GET", "POST"])
@login_required
def post_comments(post_id):
    # Authorization: GET allows Admin (simulation_read_required), POST denies Admin (simulation_required)
    from app.utils.authorization import is_simulation_role, is_security_analyst_role
    
    if request.method == "GET":
        # READ: Allow both SIMULATION_ROLE and SECURITY_ANALYST_ROLE
        if not (is_simulation_role() or is_security_analyst_role()):
            flash("Akses ditolak. Anda tidak memiliki izin untuk mengakses fitur ini.", "danger")
            return redirect(url_for("auth.login"))
    else:
        # POST (WRITE): Only allow SIMULATION_ROLE
        if not is_simulation_role():
            flash("Akses ditolak. Anda berada di Mode Security. Fitur ini hanya tersedia di Mode Simulasi.", "danger")
            return redirect(url_for("security.dashboard"))
    
    # READ operation: Use viewed session for historical access
    viewed_sess = get_viewed_session()
    active_sess = get_active_session()
    
    post = ForumPost.query.filter(
        ForumPost.id == post_id,
        build_session_filter(ForumPost, viewed_sess, context="read")
    ).first_or_404()

    if request.method == "POST":
        if not active_sess:
            flash("Tidak ada session pengujian yang aktif. Silakan mulai session baru.", "warning")
            return redirect(url_for("forum.detail", post_id=post_id))

        content = request.form.get("content", "").strip()
        if not content:
            flash("Komentar tidak boleh kosong.", "warning")
        else:
            try:
                submission_id = str(uuid.uuid4())
                # 1. XSS Detection first (create SecurityLog, add to session)
                log_content, _, _ = detect_xss(content, "comment", submission_id=submission_id)
                # 2. Create object and add to session
                comment = Comment(content=content, post_id=post_id, user_id=current_user.id, session_id=active_sess.id)
                db.session.add(comment)
                # 3. Flush to get object.id without committing
                db.session.flush()
                # 4. Update SecurityLog with object_type and object_id
                if log_content:
                    log_content.object_type = "comment"
                    log_content.object_id = comment.id
                # 5. Single commit!
                db.session.commit()
                flash("Komentar berhasil dikirim!", "success")
                return redirect(url_for("forum.detail", post_id=post_id))
            except Exception:
                db.session.rollback()
                flash("Terjadi kesalahan saat membuat komentar.", "danger")
                return redirect(url_for("forum.detail", post_id=post_id))

    return redirect(url_for("forum.detail", post_id=post_id))


@comments_bp.route("/<int:comment_id>/delete", methods=["POST"])
@login_required
@simulation_required
def delete(comment_id):
    active_sess = get_active_session()

    # ─ Session Isolation Validation ────────────────────────────────────────────
    # Pastikan objek yang dihapus berasal dari session pengujian yang aktif,
    # bukan dari session lain. Mencegah unauthorized deletion antar skenario.
    comment = Comment.query.filter(
        Comment.id == comment_id,
        build_session_filter(Comment, active_sess)
    ).first()
    
    if comment is None:
        flash("Komentar tidak berada pada skenario pengujian yang sedang aktif.", "warning")
        return redirect(url_for("forum.index"))
    
    post_id = comment.post_id

    if not active_sess:
        flash("Tidak ada session pengujian yang aktif. Silakan mulai session baru.", "warning")
        return redirect(url_for("forum.detail", post_id=post_id))

    # ─ Ownership-Based Authorization (Backend Validation)
    # Validasi dilakukan pada sisi server untuk memastikan bahwa hanya pengguna
    # yang memiliki hak akses (pemilik atau administrator) yang dapat melakukan
    # modifikasi. Permintaan yang tidak sah akan ditolak dan pengguna akan
    # diarahkan kembali ke halaman detail.
    if not can_modify_object(comment):
        flash("Anda tidak memiliki hak untuk melakukan aksi tersebut.", "danger")
        return redirect(url_for("forum.detail", post_id=post_id))

    # Sinkronisasi penghapusan SecurityLog agar statistik Dashboard tetap konsisten.
    from app.utils.session_helper import sync_delete_security_log
    sync_delete_security_log(
        session_id=comment.session_id,
        source_feature="comment",
        payloads=[comment.content]
    )

    db.session.delete(comment)
    db.session.commit()
    flash("Komentar dihapus.", "info")
    return redirect(url_for("forum.detail", post_id=post_id))


@comments_bp.route("/<int:comment_id>/edit", methods=["GET", "POST"])
@login_required
@simulation_required
def edit(comment_id):
    active_sess = get_active_session()
    
    if not active_sess:
        flash("Tidak ada session pengujian yang aktif.", "warning")
        return redirect(request.referrer or url_for("forum.index"))

    # ─ Session Isolation Validation ────────────────────────────────────────────
    # Pastikan objek yang diedit berasal dari session pengujian yang aktif,
    # bukan dari session lain. Mencegah unauthorized modification antar skenario.
    comment = Comment.query.filter(
        Comment.id == comment_id,
        build_session_filter(Comment, active_sess)
    ).first()
    
    if comment is None:
        flash("Komentar tidak berada pada skenario pengujian yang sedang aktif.", "warning")
        return redirect(url_for("forum.index"))
    
    # ─ Ownership-Based Authorization (Backend Validation)
    # Validasi dilakukan pada sisi server untuk memastikan bahwa hanya pengguna
    # yang memiliki hak akses (pemilik atau administrator) yang dapat melakukan
    # modifikasi. Permintaan yang tidak sah akan ditolak dan pengguna akan
    # diarahkan kembali ke halaman detail.
    if not can_modify_object(comment):
        flash("Anda tidak memiliki hak untuk melakukan aksi tersebut.", "danger")
        return redirect(url_for("forum.detail", post_id=comment.post_id))

    if request.method == "POST":
        content = request.form.get("content", "").strip()

        if not content:
            flash("Komentar wajib diisi.", "warning")
        else:
            try:
                submission_id = str(uuid.uuid4())
                # 1. XSS Detection first (create SecurityLog, add to session)
                log_content, _, _ = detect_xss(content, "comment", submission_id=submission_id)
                # 2. Update object
                comment.content = content
                # 3. Update SecurityLog with object_type and object_id
                if log_content:
                    log_content.object_type = "comment"
                    log_content.object_id = comment.id
                # 4. Single commit!
                db.session.commit()
                flash("Komentar berhasil diperbarui!", "success")
                return redirect(url_for("forum.detail", post_id=comment.post_id))
            except Exception:
                db.session.rollback()
                flash("Terjadi kesalahan saat memperbarui komentar.", "danger")
                return redirect(url_for("forum.detail", post_id=comment.post_id))

    return render_template("comments/edit.html", comment=comment)
