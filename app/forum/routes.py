import uuid
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models.forum import ForumPost
from app.models.comment import Comment
from app.utils.xss_detector import detect_xss
from app.utils.decorators import can_modify_object, simulation_required, simulation_read_required
from app.utils.session_helper import get_active_session, get_viewed_session, build_session_filter

forum_bp = Blueprint("forum", __name__, template_folder="../../templates/forum")


@forum_bp.route("/")
@login_required
@simulation_read_required
def index():
    # READ operation: Use viewed session for historical access
    viewed_sess = get_viewed_session()
    active_sess = get_active_session()
    from app.models.security import TestSession
    all_sessions = TestSession.query.filter_by(is_legacy=False).order_by(TestSession.started_at.desc()).all()
    posts = ForumPost.query.filter(build_session_filter(ForumPost, viewed_sess, context="read")).order_by(ForumPost.created_at.desc()).all()
    open_flag = request.args.get('open', '')
    can_modify = active_sess is not None
    return render_template("forum/index.html", posts=posts, open_flag=open_flag, can_modify=can_modify, viewed_session=viewed_sess, active_session=active_sess, all_sessions=all_sessions)


@forum_bp.route("/create", methods=["GET", "POST"])
@login_required
@simulation_required
def create():
    from app.utils.session_helper import get_active_session
    active_sess = get_active_session()
    
    if not active_sess:
        flash("Tidak ada session pengujian yang aktif. Silakan mulai session baru.", "warning")
        return redirect(url_for("forum.index"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        is_parent = request.form.get("is_parent") == "1"  # Forum parent untuk Komentar

        if not title or not content:
            flash("Judul dan konten wajib diisi.", "warning")
        else:
            try:
                # Jika Forum adalah parent untuk Komentar, JANGAN jalankan detect_xss()
                # Forum parent tetap dihitung sebagai Aktivitas/Objek, tetapi bukan Submission Payload
                if is_parent:
                    # Create object tanpa SecurityLog
                    post = ForumPost(title=title, content=content, user_id=current_user.id, session_id=active_sess.id)
                    db.session.add(post)
                    db.session.commit()
                    flash("Forum parent berhasil dibuat! (Tidak dihitung sebagai Submission Payload)", "success")
                    return redirect(url_for("forum.index"))
                else:
                    # Forum menerima payload - jalankan detect_xss() dan buat SecurityLog
                    submission_id = str(uuid.uuid4())
                    # 1. XSS Detection first (create SecurityLog, add to session)
                    log_title, _, _ = detect_xss(title, "forum", submission_id=submission_id)
                    log_content, _, _ = detect_xss(content, "forum", submission_id=submission_id)
                    # 2. Create object and add to session
                    post = ForumPost(title=title, content=content, user_id=current_user.id, session_id=active_sess.id)
                    db.session.add(post)
                    # 3. Flush to get object.id without committing
                    db.session.flush()
                    # 4. Update SecurityLogs with object_type and object_id
                    if log_title:
                        log_title.object_type = "forum_post"
                        log_title.object_id = post.id
                    if log_content:
                        log_content.object_type = "forum_post"
                        log_content.object_id = post.id
                    # 5. Single commit!
                    db.session.commit()
                    flash("Postingan berhasil dibuat!", "success")
                    return redirect(url_for("forum.index"))
            except Exception:
                db.session.rollback()
                flash("Terjadi kesalahan saat membuat postingan.", "danger")
                return redirect(url_for("forum.index"))

    return render_template("forum/create.html")


@forum_bp.route("/<int:post_id>")
@login_required
@simulation_read_required
def detail(post_id):
    # READ operation: Use viewed session for historical access
    viewed_sess = get_viewed_session()
    active_sess = get_active_session()
    from app.models.security import TestSession
    all_sessions = TestSession.query.filter_by(is_legacy=False).order_by(TestSession.started_at.desc()).all()
    
    post = ForumPost.query.filter(
        ForumPost.id == post_id,
        build_session_filter(ForumPost, viewed_sess, context="read")
    ).first_or_404()
    
    comments = Comment.query.filter(
        Comment.post_id == post_id,
        build_session_filter(Comment, viewed_sess, context="read")
    ).order_by(Comment.created_at.desc()).all()
    
    # ─ Ownership-Based Authorization
    # Controller menghitung status modifikasi untuk setiap entitas berdasarkan ownership.
    # Template hanya menerima boolean untuk menampilkan/menyembunyikan tombol.
    can_modify_post = can_modify_object(post) and active_sess is not None
    
    # Untuk setiap komentar, hitung hak akses modifikasi
    comments_with_perms = [
        {
            'comment': c,
            'can_modify': can_modify_object(c) and active_sess is not None
        }
        for c in comments
    ]
    
    return render_template(
        "forum/detail.html",
        post=post,
        comments=comments_with_perms,
        can_modify_post=can_modify_post,
        viewed_session=viewed_sess,
        active_session=active_sess,
        all_sessions=all_sessions
    )


@forum_bp.route("/<int:post_id>/delete", methods=["POST"])
@login_required
@simulation_required
def delete(post_id):
    active_sess = get_active_session()
    if not active_sess:
        flash("Tidak ada session pengujian yang aktif. Silakan mulai session baru.", "warning")
        return redirect(url_for("forum.index"))

    # ─ Session Isolation Validation ────────────────────────────────────────────
    # Pastikan objek yang dihapus berasal dari session pengujian yang aktif,
    # bukan dari session lain. Mencegah unauthorized deletion antar skenario.
    post = ForumPost.query.filter(
        ForumPost.id == post_id,
        build_session_filter(ForumPost, active_sess, context="write")
    ).first()
    
    if post is None:
        flash("Postingan tidak berada pada skenario pengujian yang sedang aktif.", "warning")
        return redirect(url_for("forum.index"))
    
    # ─ Ownership-Based Authorization (Backend Validation)
    # Validasi dilakukan pada sisi server untuk memastikan bahwa hanya pengguna
    # yang memiliki hak akses (pemilik atau administrator) yang dapat melakukan
    # modifikasi. Permintaan yang tidak sah akan ditolak dan pengguna akan
    # diarahkan kembali ke halaman detail.
    if not can_modify_object(post):
        flash("Anda tidak memiliki hak untuk melakukan aksi tersebut.", "danger")
        return redirect(url_for("forum.detail", post_id=post.id))

    # Sinkronisasi penghapusan SecurityLog agar statistik Dashboard tetap konsisten.
    from app.utils.session_helper import sync_delete_security_log
    sync_delete_security_log(
        session_id=post.session_id,
        source_feature="forum",
        payloads=[post.title, post.content]
    )

    # Hapus komentar terkait terlebih dahulu untuk menghindari
    # IntegrityError saat foreign key tidak dapat di-null-kan.
    Comment.query.filter_by(post_id=post.id).delete()
    db.session.delete(post)
    db.session.commit()
    flash("Postingan dihapus.", "info")
    return redirect(url_for("forum.index"))


@forum_bp.route("/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
@simulation_required
def edit(post_id):
    active_sess = get_active_session()
    
    if not active_sess:
        flash("Tidak ada session pengujian yang aktif. Silakan mulai session baru.", "warning")
        return redirect(url_for("forum.index"))

    # ─ Session Isolation Validation ────────────────────────────────────────────
    # Pastikan objek yang diedit berasal dari session pengujian yang aktif,
    # bukan dari session lain. Mencegah unauthorized modification antar skenario.
    post = ForumPost.query.filter(
        ForumPost.id == post_id,
        build_session_filter(ForumPost, active_sess, context="write")
    ).first()
    
    if post is None:
        flash("Postingan tidak berada pada skenario pengujian yang sedang aktif.", "warning")
        return redirect(url_for("forum.index"))
    
    # ─ Ownership-Based Authorization (Backend Validation)
    # Validasi dilakukan pada sisi server untuk memastikan bahwa hanya pengguna
    # yang memiliki hak akses (pemilik atau administrator) yang dapat melakukan
    # modifikasi. Permintaan yang tidak sah akan ditolak dan pengguna akan
    # diarahkan kembali ke halaman detail.
    if not can_modify_object(post):
        flash("Anda tidak memiliki hak untuk melakukan aksi tersebut.", "danger")
        return redirect(url_for("forum.detail", post_id=post.id))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()

        if not title or not content:
            flash("Judul dan konten wajib diisi.", "warning")
        else:
            try:
                # Generate single submission_id for this payload edit
                submission_id = str(uuid.uuid4())
                # 1. XSS Detection first (create SecurityLog, add to session)
                log_title, _, _ = detect_xss(title, "forum", submission_id=submission_id)
                log_content, _, _ = detect_xss(content, "forum", submission_id=submission_id)
                # 2. Update object
                post.title = title
                post.content = content
                # 3. Update SecurityLogs with object_type and object_id
                if log_title:
                    log_title.object_type = "forum_post"
                    log_title.object_id = post.id
                if log_content:
                    log_content.object_type = "forum_post"
                    log_content.object_id = post.id
                # 4. Single commit!
                db.session.commit()
                flash("Postingan berhasil diperbarui!", "success")
                return redirect(url_for("forum.detail", post_id=post.id))
            except Exception:
                db.session.rollback()
                flash("Terjadi kesalahan saat memperbarui postingan.", "danger")
                return redirect(url_for("forum.detail", post_id=post.id))

    return render_template("forum/edit.html", post=post)
