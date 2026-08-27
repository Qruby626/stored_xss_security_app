"""Helpers for Simple Test Session Management."""
from __future__ import annotations

from urllib.parse import urlparse
from flask import request
from sqlalchemy import func

from app import db
from app.models.security import TestSession, SecurityLog, CspReport


def normalize_document_uri(uri: str) -> str:
    """
    Menormalisasi document URI agar URI yang merepresentasikan halaman yang sama
    dihitung sebagai satu payload unik.
    """
    if not uri:
        return "/"

    parsed = urlparse(uri)
    path = parsed.path.rstrip("/")

    if not path:
        path = "/"

    return path


def get_active_session() -> TestSession | None:
    """Return the currently active test session, if any."""
    return (
        TestSession.query.filter_by(status="active")
        .order_by(TestSession.started_at.desc())
        .first()
    )


def resolve_simulation_session_id() -> int | None:
    """
    Resolve session ID for Simulation Module READ operations.
    
    Mekanisme ini melacak pilihan sesi secara eksplisit dengan urutan prioritas:
    1. Parameter query `session_id` (pilihan manual dari URL).
    2. Nilai `viewed_session_id` yang tersimpan di Flask Session (prioritas 2).
    3. Sesi pengujian yang sedang aktif (DEFAULT jika belum ada selected session).
    4. Fallback awal ke sesi terbaru dalam database.
    
    PERBEDAAN berdasarkan ROLE:
    - STUDENT tanpa explicit session_id: selalu gunakan ACTIVE SESSION
    - ADMIN tanpa explicit session_id: gunakan viewed_session_id (jika ada), fallback ke ACTIVE SESSION
    
    PERBEDAAN dengan resolve_session_id():
    - Prioritas viewed_session_id > active_session (untuk Simulation Admin)
    - Tujuan: Selected session tidak boleh tergantikan oleh active_session untuk Admin
    - User dapat melihat finished session dengan explicit ?session_id
    - Selected session tetap konsisten seluruh navigasi Simulation untuk Admin
    - Student selalu membaca data dari ACTIVE SESSION jika tidak ada explicit session_id
    """
    from flask import session as flask_session
    from flask_login import current_user

    # 1. Cek parameter query string (pilihan manual dari URL)
    raw = request.args.get("session_id", "").strip()
    if raw.isdigit():
        sess_id = int(raw)
        s = TestSession.query.get(sess_id)
        if s:
            flask_session["viewed_session_id"] = s.id
            return s.id

    # 2. Cek role untuk menentukan prioritas fallback
    # Student tanpa explicit session_id: selalu gunakan ACTIVE SESSION
    if current_user.is_authenticated and getattr(current_user, "role", None) == "student":
        active = get_active_session()
        if active:
            return active.id
        # Jika tidak ada ACTIVE SESSION, return None
        # JANGAN fallback ke most_recent atau viewed_session_id lama
        return None

    # 3. Admin atau tanpa role: gunakan viewed_session_id (prioritas 2)
    stored_id = flask_session.get("viewed_session_id")
    if stored_id:
        s = TestSession.query.get(stored_id)
        if s:
            return s.id

    # 4. Gunakan sesi aktif saat ini sebagai DEFAULT (hanya jika belum ada selected session)
    active = get_active_session()
    if active:
        # JANGAN overwrite viewed_session_id di Flask session
        # Hanya return Active Session ID sebagai DEFAULT
        return active.id

    # 5. Fallback ke sesi terbaru sebagai default awal
    most_recent = (
        TestSession.query
        .filter_by(is_legacy=False)
        .order_by(TestSession.started_at.desc())
        .first()
    )
    if most_recent:
        return most_recent.id

    return None


def get_viewed_session() -> TestSession | None:
    """
    Return the currently viewed/selected test session for READ operations.
    
    This function returns the session that the user has selected for viewing,
    which can be either an active session or a finished session.
    Used for READ/REVIEW/AUDIT operations in Modul Simulasi.
    
    IMPORTANT: Uses resolve_simulation_session_id() instead of resolve_session_id()
    to prioritize active_session over Flask viewed_session_id for Simulation Module.
    """
    viewed_id = resolve_simulation_session_id()
    if viewed_id:
        return db.session.get(TestSession, viewed_id)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# DOKUMENTASI STATE SESSION (Perbaikan 4 & 5)
# ─────────────────────────────────────────────────────────────────────────────
# Aplikasi memiliki 3 state skenario pengujian utama:
#
# 1. ACTIVE
#    - Skenario pengujian sedang berjalan (get_active_session() != None).
#    - Aplikasi menerima input payload baru (Forum, Komentar, Chat, Pengumuman).
#    - Security Engine memproses deteksi secara real-time dan menyimpan hasilnya ke SecurityLog.
#    - Dashboard Security menampilkan metrik langsung dari skenario aktif ini.
#
# 2. COMPLETED
#    - Skenario pengujian telah selesai/dihentikan (status="finished").
#    - Seluruh data pengujian (Forum, Komentar, Chat, Pengumuman) dikunci menjadi READ-ONLY.
#    - Statistik dashboard tetap menampilkan metrik sesuai skenario yang diselesaikan/dipilih.
#    - Catatan riwayat/histori tetap dipertahankan untuk kebutuhan audit dan bukti pengujian.
#
# 3. NO SESSION
#    - Tidak ada sesi aktif dalam sistem. Seluruh operasi WRITE ditolak secara ketat.
#    - Pengguna dapat memilih sesi manapun melalui dashboard dropdown untuk meninjau data
#      histori pengujian secara read-only.
#
# METODOLOGI PENELITIAN & AKADEMIK (BAB IV SKRIPSI):
# Session yang telah selesai tidak dihapus agar histori pengujian tetap tersedia sebagai bukti
# eksperimen. Data hanya berubah menjadi read-only sehingga integritas hasil pengujian tetap
# terjaga dan dapat digunakan kembali untuk analisis pada Bab IV maupun proses verifikasi saat sidang.
# ─────────────────────────────────────────────────────────────────────────────

def resolve_session_id() -> int | None:
    """
    Resolve the currently viewed/selected session ID.
    
    Mekanisme ini melacak pilihan sesi secara eksplisit dengan urutan prioritas:
    1. Parameter query `session_id` (mengubah sesi yang disimpan di cookie session).
    2. Nilai `viewed_session_id` yang tersimpan di Flask Session.
    3. Sesi pengujian yang sedang aktif (jika ada).
    4. Fallback awal ke sesi terbaru dalam database.
    """
    from flask import session as flask_session

    # 1. Cek parameter query string (pilihan manual dari dropdown)
    raw = request.args.get("session_id", "").strip()
    if raw.isdigit():
        sess_id = int(raw)
        s = TestSession.query.get(sess_id)
        if s:
            flask_session["viewed_session_id"] = s.id
            return s.id

    # 2. Cek apakah ada pilihan sesi sebelumnya yang tersimpan di Flask Session
    stored_id = flask_session.get("viewed_session_id")
    if stored_id:
        s = TestSession.query.get(stored_id)
        if s:
            return s.id

    # 3. Jika tidak ada, gunakan sesi aktif saat ini sebagai fallback (READ ONLY)
    active = get_active_session()
    if active:
        # JANGAN overwrite viewed_session_id di Flask session
        # Hanya return Active Session ID sebagai fallback
        return active.id

    # 4. Jika tidak ada sesi aktif, cari sesi terbaru sebagai default awal (READ ONLY)
    most_recent = (
        TestSession.query
        .filter_by(is_legacy=False)
        .order_by(TestSession.started_at.desc())
        .first()
    )
    if most_recent:
        # JANGAN overwrite viewed_session_id di Flask session
        # Hanya return most_recent session ID sebagai fallback
        return most_recent.id

    return None


def _extract_object_reference_from_uri(uri: str | None) -> tuple[str | None, int | None]:
    """Extract (object_type, object_id) from a page URL when possible.

    Examples:
      /forum/12 -> (forum_post, 12)
      /announcements/5 -> (announcement, 5)
      /chat/8 -> (chat_message, 8)
      /comments/3 -> (comment, 3)
    """
    if not uri:
        return None, None

    parsed = urlparse(uri)
    path = parsed.path.strip("/")
    if not path:
        return None, None

    segments = path.split("/")
    if len(segments) < 2:
        return None, None

    prefix = segments[0].lower()
    raw_id = segments[-1]
    if not raw_id.isdigit():
        return None, None

    object_id = int(raw_id)
    mapping = {
        "forum": "forum_post",
        "announcements": "announcement",
        "announcement": "announcement",
        "chat": "chat_message",
        "comments": "comment",
        "comment": "comment",
    }
    object_type = mapping.get(prefix)
    if object_type is None:
        return None, None

    return object_type, object_id


def resolve_csp_report_submission_ids(
    session_id: int,
    document_uri: str | None,
    blocked_uri: str | None,
) -> set[str]:
    """Resolve the submission_id(s) behind a CSP report by matching page/object metadata.

    Browser CSP reports do not include a submission_id. We therefore map the report to
    the object page that triggered it (forum/comment/announcement/chat) and then resolve
    the corresponding SecurityLog rows in the same session.
    """
    candidates: set[str] = set()

    for uri in (document_uri, blocked_uri):
        object_type, object_id = _extract_object_reference_from_uri(uri)
        if object_type is None or object_id is None:
            continue

        rows = (
            SecurityLog.query
            .filter_by(session_id=session_id, object_type=object_type, object_id=object_id)
            .filter(SecurityLog.submission_id.isnot(None))
            .all()
        )
        for row in rows:
            if row.submission_id:
                candidates.add(row.submission_id)

    return candidates


def get_session_stats(session_id: int) -> dict:
    """Compute dashboard metrics scoped to a single test session (Unit: Submission).

    Metrics returned
    ----------------
    - total_objects   : jumlah seluruh aktivitas/objek yang tercatat (ForumPost, Comment, Announcement, ChatMessage).
                       Termasuk Forum parent untuk komentar yang tidak menerima payload pengujian.
                       TIDAK digunakan sebagai denominator Detection Rate atau Blocking Rate.

    - total_tested    : jumlah submission_id unik untuk submission payload yang diuji (forum, comment, announcement, chat).
                       Hanya menghitung submission yang menerima payload pengujian pada 4 target:
                       - Forum Diskusi (bukan Forum parent untuk komentar)
                       - Kolom Komentar
                       - Form Pengumuman
                       - Chat Sederhana
                       Digunakan sebagai denominator Detection Rate dan Blocking Rate.

    - total_detected  : jumlah submission_id unik yang memiliki setidaknya satu log DETECTED.
                       Submission yang teridentifikasi oleh Rule-Based Detection.
                       Digunakan sebagai numerator Detection Rate.

    - total_safe      : total log SAFE (untuk referensi teknis).
                       TIDAK digunakan dalam perhitungan Detection Rate atau Blocking Rate.

    - total_csp       : jumlah submission_id unik yang menghasilkan CSP Violation Report.
                       Satu submission dengan multiple CSP Reports hanya dihitung sekali.
                       Submission_id di-filter untuk hanya menyertakan yang masih valid (masih ada di SecurityLog pada session yang sama).

    - total_blocked   : jumlah submission_id unik yang terindikasi diblokir CSP berdasarkan CSP Violation Report.
                       CATATAN: Dalam implementasi saat ini, total_blocked diset sama dengan total_csp
                       karena sistem tidak memiliki tracking eksplisit untuk status "blocked" dari CSP.
                       CSP Report adalah indikator pelanggaran kebijakan CSP yang digunakan sebagai
                       indikator pemblokiran dalam penelitian ini, namun tidak selalu merepresentasikan
                       pemblokiran eksekusi script secara eksplisit.
                       Digunakan sebagai numerator Blocking Rate.

    - detection_rate  : (total_detected / total_tested) × 100
                       Denominator: Submission Payload Diuji (bukan Aktivitas/Objek Tercatat).

    - blocking_rate   : (total_blocked / total_tested) × 100
                       Denominator: Submission Payload Diuji (bukan Aktivitas/Objek Tercatat).
    """
    # Hitung total seluruh aktivitas/objek yang tercatat (ForumPost, Comment, Announcement, ChatMessage)
    from app.models.forum import ForumPost
    from app.models.comment import Comment
    from app.models.announcement import Announcement
    from app.models.chat import ChatMessage

    total_objects = (
        db.session.query(func.count())
        .select_from(
            db.session.query(ForumPost.id).filter(ForumPost.session_id == session_id).union_all(
                db.session.query(Comment.id).filter(Comment.session_id == session_id).union_all(
                    db.session.query(Announcement.id).filter(Announcement.session_id == session_id).union_all(
                        db.session.query(ChatMessage.id).filter(ChatMessage.session_id == session_id)
                    )
                )
            ).subquery()
        )
        .scalar()
    ) or 0

    # Hitung submission payload yang diuji (hanya forum, comment, announcement, chat)
    # Komentar pada posting Forum induk untuk pengujian Komentar tidak dihitung sebagai submission payload
    total_tested_result = (
        db.session.query(func.count(func.distinct(SecurityLog.submission_id)))
        .filter(SecurityLog.session_id == session_id)
        .filter(SecurityLog.source_feature.in_(["forum", "comment", "announcement", "chat"]))
        .first()
    )
    total_tested = total_tested_result[0] if total_tested_result else 0

    total_detected_result = (
        db.session.query(func.count(func.distinct(SecurityLog.submission_id)))
        .filter(
            SecurityLog.session_id == session_id,
            SecurityLog.status == "DETECTED"
        )
        .first()
    )
    total_detected = total_detected_result[0] if total_detected_result else 0

    total_safe = SecurityLog.query.filter_by(
        session_id=session_id, status="SAFE"
    ).count()

    # KPI Total Laporan CSP harus dihitung berdasarkan submission unik yang menghasilkan
    # paling sedikit satu CSP report, bukan jumlah seluruh baris laporan browser.
    # Hanya hitung submission_id yang masih valid (masih ada di SecurityLog pada session yang sama).
    valid_csp_submission_ids = (
        db.session.query(CspReport.submission_id)
        .filter(CspReport.session_id == session_id)
        .filter(CspReport.submission_id.isnot(None))
        .filter(
            CspReport.submission_id.in_(
                db.session.query(SecurityLog.submission_id)
                .filter(SecurityLog.session_id == session_id)
                .filter(SecurityLog.submission_id.isnot(None))
                .distinct()
            )
        )
        .distinct()
        .all()
    )
    total_csp = len(valid_csp_submission_ids)

    # Catatan: Dalam implementasi saat ini, total_blocked diset sama dengan total_csp
    # karena sistem tidak memiliki tracking eksplisit untuk status "blocked" dari CSP.
    # CSP Report adalah indikator pelanggaran kebijakan CSP, namun tidak selalu
    # merepresentasikan pemblokiran eksekusi script. Untuk akurasi yang lebih tinggi,
    # disarankan menambahkan field khusus untuk tracking status blocked submission.
    total_blocked = total_csp

    detection_rate = round(
        (total_detected / total_tested * 100) if total_tested > 0 else 0, 2
    )
    blocking_rate = round(
        (total_blocked / total_tested * 100) if total_tested > 0 else 0, 2
    )

    return {
        "total_objects": total_objects,
        "total_tested": total_tested,
        "total_detected": total_detected,
        "total_safe": total_safe,
        "total_csp": total_csp,
        "total_blocked": total_blocked,
        "detection_rate": detection_rate,
        "blocking_rate": blocking_rate,
    }


def build_session_filter(model, active_session: TestSession | None = None, context: str = "auto"):
    """
    Build a session filter query.
    
    Args:
        model: The SQLAlchemy model to filter
        active_session: The active test session (for WRITE operations)
        context: The operation context - "write", "read", or "auto"
                 - "write": Always use active_session
                 - "read": Use viewed_session if available, fallback to active_session
                 - "auto": Original behavior (active_session first, fallback to viewed)
    
    Jika sesi pengujian aktif sedang berjalan, kita memfilter data berdasarkan sesi aktif.
    Jika tidak ada sesi aktif, kita memfilter data berdasarkan sesi yang saat ini
    sedang dipilih/ditinjau (resolved viewed session) untuk menampilkan data historis.
    """
    if not hasattr(model, "session_id"):
        raise ValueError(
            f"Model {model.__name__} tidak memiliki atribut session_id."
        )
    
    # WRITE context: Always use active_session
    if context == "write":
        if active_session:
            return model.session_id == active_session.id
        return model.session_id.is_(None)
    
    # READ context: Use passed session object first, fallback to resolve_simulation_session_id()
    if context == "read":
        if active_session:
            return model.session_id == active_session.id
        viewed_id = resolve_simulation_session_id()
        if viewed_id:
            return model.session_id == viewed_id
        return model.session_id.is_(None)
    
    # AUTO context: Original behavior (use active_session first, fallback to resolve_simulation_session_id)
    if active_session:
        return model.session_id == active_session.id

    viewed_id = resolve_simulation_session_id()
    if viewed_id:
        return model.session_id == viewed_id

    return model.session_id.is_(None)


def get_session_status(active_session: TestSession | None) -> str:
    """Return 'active' | 'finished' | 'none' based on TestSessions in DB."""
    if active_session:
        return "active"
    
    # Check for any finished test session (ignoring legacy sessions)
    has_finished = (
        TestSession.query
        .filter_by(status="finished", is_legacy=False)
        .first() is not None
    )
    if has_finished:
        return "finished"
    return "none"


def get_session_history_rows() -> list[dict]:
    """Build summary rows for the Test Sessions history page."""
    sessions = (
        TestSession.query
        .filter_by(is_legacy=False)
        .order_by(TestSession.started_at.desc())
        .all()
    )
    rows = []
    for session in sessions:
        stats = get_session_stats(session.id)
        rows.append(
            {
                "session": session,
                "payload_count": stats["total_tested"],
                "detection_rate": stats["detection_rate"],
                "blocking_rate": stats["blocking_rate"],
            }
        )
    return rows


def chart_data_for_session(session_id: int) -> dict:
    """Return chart JSON data filtered by session_id.
    
    Menggunakan submission_id unik agar konsisten dengan metrik Dashboard Keamanan.
    Satu payload (submission_id) dihitung sebagai 1, terlepas berapa log yang dihasilkan.
    
    Status agregat: jika minimal satu log DETECTED maka status = DETECTED.
    
    Catatan: Fungsi ini menghitung submission unik per feature, bukan log count.
    Setiap submission_id hanya dihitung sekali per feature, meskipun menghasilkan multiple logs.
    """
    # Ambil semua logs per submission
    all_logs = (
        db.session.query(
            SecurityLog.submission_id,
            SecurityLog.source_feature,
            SecurityLog.status
        )
        .filter(SecurityLog.session_id == session_id)
        .all()
    )
    
    # Agregasi status per submission di Python
    # Aturan: jika minimal satu log DETECTED -> status = DETECTED
    submission_status = {}
    for submission_id, feature, status in all_logs:
        key = (submission_id, feature)
        if key not in submission_status:
            submission_status[key] = status
        else:
            # Jika sudah ada status dan yang baru adalah DETECTED, override
            if status == 'DETECTED':
                submission_status[key] = 'DETECTED'
    
    # Agregasi ke level feature (count submission unik per feature)
    data: dict = {}
    for (submission_id, feature), status in submission_status.items():
        data.setdefault(feature, {"DETECTED": 0, "SAFE": 0})
        data[feature][status] += 1
    
    return data


# ─────────────────────────────────────────────────────────────────────────────
# SECURITY LOG SYNCHRONIZATION HELPER
# ─────────────────────────────────────────────────────────────────────────────

def sync_delete_security_log(session_id: int | None, source_feature: str, payloads: list[str | None]):
    """Menghapus SecurityLog yang berkaitan dengan payload tertentu."""
    if session_id is None:
        return
    
    payloads = [p for p in payloads if p]
    if not payloads:
        return
    
    SecurityLog.query.filter(
        SecurityLog.session_id == session_id,
        SecurityLog.source_feature == source_feature,
        SecurityLog.payload.in_(payloads),
    ).delete(synchronize_session=False)
