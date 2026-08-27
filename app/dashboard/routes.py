from flask import Blueprint, render_template
from flask_login import login_required, current_user
from app.models.forum import ForumPost
from app.models.chat import ChatMessage
from app.models.announcement import Announcement
from app.models.comment import Comment
from app.utils.decorators import simulation_read_required

dashboard_bp = Blueprint("dashboard", __name__, template_folder="../../templates/dashboard")


@dashboard_bp.route("/dashboard", methods=["GET"])
@login_required
@simulation_read_required
def index():
    from app.utils.session_helper import get_active_session, get_viewed_session, build_session_filter

    # Dashboard Simulasi menggunakan viewed_session (untuk Admin read-only) atau active_session (default)
    active_session = get_active_session()
    viewed_session = get_viewed_session()

    # Gunakan viewed_session jika tersedia (untuk Admin/selected session), otherwise active_session
    selected_session = viewed_session if viewed_session else active_session

    # Jika tidak ada session sama sekali, tampilkan data kosong
    if not selected_session:
        return render_template(
            "dashboard/index.html",
            total_posts=0,
            total_chats=0,
            total_ann=0,
            total_comments=0,
            recent_posts=[],
            recent_activities=[],
            viewed_session=viewed_session,
            active_session=active_session,
        )

    # ── Target Pengujian (Statistik umum) ─────────────────────────
    total_posts = ForumPost.query.filter(build_session_filter(ForumPost, selected_session)).count()
    total_chats = ChatMessage.query.filter(build_session_filter(ChatMessage, selected_session)).count()
    total_ann = Announcement.query.filter(build_session_filter(Announcement, selected_session)).count()
    total_comments = Comment.query.filter(build_session_filter(Comment, selected_session)).count()

    # ── Postingan Forum Terbaru (Maksimal 5) ──────────────────────
    recent_posts = (ForumPost.query
                    .filter(build_session_filter(ForumPost, selected_session))
                    .order_by(ForumPost.created_at.desc())
                    .limit(5).all())

    # ── Riwayat Aktivitas Saya (Maksimal 5 untuk current_user) ────
    user_id = current_user.id
    activities = []

    # 1. Forum Posts
    my_posts = ForumPost.query.filter_by(user_id=user_id).filter(build_session_filter(ForumPost, selected_session)).order_by(ForumPost.created_at.desc()).limit(5).all()
    for p in my_posts:
        activities.append({
            "feature": "Forum Diskusi",
            "action": "Membuat postingan",
            "created_at": p.created_at,
            "status": "Terkirim",
            "icon": "bi-chat-left-text text-primary"
        })

    # 2. Comments
    my_comments = Comment.query.filter_by(user_id=user_id).filter(build_session_filter(Comment, selected_session)).order_by(Comment.created_at.desc()).limit(5).all()
    for c in my_comments:
        activities.append({
            "feature": "Komentar",
            "action": "Mengirim komentar",
            "created_at": c.created_at,
            "status": "Terkirim",
            "icon": "bi-reply text-success"
        })

    # 3. Chat Messages
    my_chats = ChatMessage.query.filter_by(user_id=user_id).filter(build_session_filter(ChatMessage, selected_session)).order_by(ChatMessage.created_at.desc()).limit(5).all()
    for ch in my_chats:
        activities.append({
            "feature": "Chat",
            "action": "Mengirim chat",
            "created_at": ch.created_at,
            "status": "Terkirim",
            "icon": "bi-messenger text-info"
        })

    # 4. Announcements (only if they are admin/can post)
    my_anns = Announcement.query.filter_by(user_id=user_id).filter(build_session_filter(Announcement, selected_session)).order_by(Announcement.created_at.desc()).limit(5).all()
    for a in my_anns:
        activities.append({
            "feature": "Pengumuman",
            "action": "Membuat pengumuman",
            "created_at": a.created_at,
            "status": "Diterbitkan",
            "icon": "bi-megaphone text-warning"
        })

    # Gabungkan semua aktivitas, urutkan berdasarkan waktu (descending), ambil 5 teratas
    activities.sort(key=lambda x: x["created_at"], reverse=True)
    recent_activities = activities[:5]

    return render_template(
        "dashboard/index.html",
        total_posts=total_posts,
        total_chats=total_chats,
        total_ann=total_ann,
        total_comments=total_comments,
        recent_posts=recent_posts,
        recent_activities=recent_activities,
        viewed_session=viewed_session,
        active_session=active_session,
    )
