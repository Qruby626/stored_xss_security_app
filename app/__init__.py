"""
Application Factory — XSS Security Research Platform.

Arsitektur: Flask Application Factory dengan Blueprint modular.
Keamanan : Flask-Talisman (CSP), Flask-WTF (CSRF), Flask-Login (auth).
Migrasi  : Flask-Migrate (Alembic) — gunakan 'flask db upgrade' untuk skema terbaru.
"""
from flask import Flask, redirect, url_for, render_template, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from config import Config

# ── Extension instances (diinisialisasi di create_app) ────────────────────────
db           = SQLAlchemy()
migrate      = Migrate()          # Flask-Migrate / Alembic
login_manager = LoginManager()
csrf         = CSRFProtect()
talisman     = Talisman()


def create_app(config_class: type = Config) -> Flask:
    """
    Application Factory.

    Membuat dan mengonfigurasi instance Flask beserta semua extension dan Blueprint.
    Tidak memanggil db.create_all() — gunakan Flask-Migrate untuk manajemen skema.
    """
    app = Flask(__name__)
    app.config.from_object(config_class)

    # ── Extensions ────────────────────────────────────────────────────────────
    db.init_app(app)

    # Flask-Migrate: gunakan 'flask db init / migrate / upgrade'
    # untuk membuat dan mengelola skema database.
    migrate.init_app(app, db)

    csrf.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view         = "auth.login"
    login_manager.login_message      = "Silakan login untuk mengakses halaman ini."
    login_manager.login_message_category = "warning"

    # ── CSP Policy (Flask-Talisman) ────────────────────────────────────────────
    #
    # Catatan keamanan:
    # • CSP Nonce digunakan untuk mencegah eksekusi script inline yang tidak sah.
    #   Flask-Talisman membuat nonce baru per-request via secrets.token_urlsafe()
    #   dan menyisipkannya ke header 'script-src' secara otomatis.
    # • script-src TIDAK menggunakan 'unsafe-inline'. Semua script inline di
    #   template wajib menyertakan nonce="{{ csp_nonce() }}".
    # • style-src menggunakan 'unsafe-inline' HANYA untuk kompatibilitas
    #   Bootstrap 5 yang memerlukan inline style pada beberapa komponen.
    #   Ini adalah trade-off yang diterima untuk antarmuka penelitian.
    # • frame-ancestors 'none' mencegah aplikasi di-embed dalam iframe (anti-clickjacking).
    # • form-action 'self' membatasi tujuan pengiriman form hanya ke domain sendiri.
    #
    csp_policy = {
        # Sumber default untuk semua resource yang tidak tercakup directive lain
        "default-src": "'self'",

        # Script: 'self' + CDN + nonce dinamis per-request.
        # Flask-Talisman akan menambahkan 'nonce-<value>' secara otomatis
        # karena script-src ada dalam content_security_policy_nonce_in.
        # TIDAK menggunakan 'unsafe-inline'.
        "script-src": [
            "'self'",
            "https://cdn.jsdelivr.net",
        ],

        # Style: 'unsafe-inline' diizinkan HANYA untuk kompatibilitas Bootstrap 5.
        # script-src tetap tidak menggunakan 'unsafe-inline'.
        "style-src": [
            "'self'",
            "https://cdn.jsdelivr.net",
            "https://fonts.googleapis.com",
            "'unsafe-inline'",
        ],

        # Font: Google Fonts + CDN
        "font-src": [
            "'self'",
            "https://fonts.gstatic.com",
            "https://cdn.jsdelivr.net",
        ],

        # Image: 'self' + data URI (untuk favicon & base64 inline image)
        "img-src": ["'self'", "data:"],

        # Plugin/object diblokir total
        "object-src": "'none'",

        # Batasi base URL hanya ke domain sendiri (anti base-tag hijacking)
        "base-uri": "'self'",

        # Cegah aplikasi di-embed dalam iframe (anti-clickjacking)
        "frame-ancestors": "'none'",

        # Batasi tujuan form hanya ke domain sendiri
        "form-action": "'self'",

        # Endpoint penerima laporan pelanggaran CSP dari browser
        "report-uri": config_class.CSP_REPORT_URI,
    }

    # ── CSP Bypass Hook (Security Toggle) ──────────────────────────────────────
    # Hook ini harus diregister SEBELUM talisman.init_app agar dieksekusi TERAKHIR
    # (Flask mengeksekusi after_request secara reverse-order).
    @app.after_request
    def apply_csp_toggle(response: Response) -> Response:
        """
        Jika SecuritySetting.csp_nonce_enabled = False, hapus header
        Content-Security-Policy dari HTTP response.
        """
        try:
            from app.models.security import SecuritySetting
            settings = SecuritySetting.get_settings()
            if not settings.csp_nonce_enabled:
                response.headers.pop("Content-Security-Policy", None)
                response.headers.pop("Content-Security-Policy-Report-Only", None)
        except Exception:
            pass  # fallback: biarkan CSP tetap aktif
        return response

    talisman.init_app(
        app,
        force_https=config_class.FORCE_HTTPS,
        content_security_policy=csp_policy,
        # Talisman otomatis menambahkan 'nonce-<value>' ke directive ini
        content_security_policy_nonce_in=["script-src"],
    )

    # ── Blueprints ─────────────────────────────────────────────────────────────
    from app.auth.routes          import auth_bp
    from app.dashboard.routes     import dashboard_bp
    from app.forum.routes         import forum_bp
    from app.comments.routes      import comments_bp
    from app.announcements.routes import announcements_bp
    from app.chat.routes          import chat_bp
    from app.security.routes      import security_bp
    from app.testing.routes       import testing_bp

    app.register_blueprint(auth_bp,          url_prefix="/auth")
    app.register_blueprint(dashboard_bp)                            # /dashboard
    app.register_blueprint(forum_bp,         url_prefix="/forum")
    app.register_blueprint(comments_bp,      url_prefix="/comments")
    app.register_blueprint(announcements_bp, url_prefix="/announcements")
    app.register_blueprint(chat_bp,          url_prefix="/chat")
    app.register_blueprint(security_bp,      url_prefix="/security")
    app.register_blueprint(testing_bp,       url_prefix="/testing")

    # ── CSP Report endpoint ────────────────────────────────────────────────────
    from app.security.csp_report import csp_report_bp
    app.register_blueprint(csp_report_bp)

    # ── Root route — Landing / Entry Page ─────────────────────────────────────
    @app.route("/")
    def index():
        from flask_login import current_user
        if current_user.is_authenticated:
            # Pengguna yang sudah login langsung diarahkan ke dashboard sesuai role.
            # Mekanisme authorization tidak berubah.
            from app.utils.authorization import get_default_dashboard_url
            return redirect(get_default_dashboard_url())
        # Pengguna belum login → tampilkan Landing / Entry Page.
        return render_template("landing.html")

    # (apply_csp_toggle telah dipindahkan ke atas sebelum talisman.init_app)

    # ── Template Context Processor ─────────────────────────────────────────────
    @app.context_processor
    def inject_security_status():
        """
        Injeksikan variabel status ke SEMUA template (Single Source of Truth Template Context).

        Variabel legacy (pertahanan untuk backward-compat):
            csp_active, rule_detection_active, session_status,
            can_modify, is_session_readonly

        Variabel BARU — Functional RBAC (dipakai oleh template base.html & semua UI):
            functional_role       : SIMULATION_ROLE | SECURITY_ANALYST_ROLE | UNKNOWN_ROLE
            mode_label            : "Student" | "Admin"
            is_simulation_mode    : bool → True jika Functional Role == Simulation
            is_security_mode      : bool → True jika Functional Role == Security Analyst
        """
        # ── Functional Role & Mode Operasi (precompute, TIDAK ada hardcode role di template)
        from flask_login import current_user as _cu
        from app.utils.authorization import (
            get_functional_role,
            get_mode_label,
            SIMULATION_ROLE,
            SECURITY_ANALYST_ROLE,
        )
        functional_role = get_functional_role(_cu)
        mode_label = get_mode_label(functional_role)
        is_simulation_mode = (functional_role == SIMULATION_ROLE)
        is_security_mode = (functional_role == SECURITY_ANALYST_ROLE)

        try:
            from app.models.security import SecuritySetting, TestSession
            settings = SecuritySetting.get_settings()
            from app.utils.session_helper import get_active_session, get_viewed_session, get_session_status
            active_session = get_active_session()
            viewed_session = get_viewed_session()
            all_sessions = TestSession.query.filter_by(is_legacy=False).order_by(TestSession.started_at.desc()).all()
            status = get_session_status(active_session)
            return {
                "csp_active": settings.csp_nonce_enabled,
                "rule_detection_active": settings.rule_detection_enabled,
                "session_status": status,
                "can_modify": active_session is not None,
                "is_session_readonly": active_session is None,
                # ── Functional RBAC vars baru ────────────────────────────────
                "functional_role": functional_role,
                "mode_label": mode_label,
                "is_simulation_mode": is_simulation_mode,
                "is_security_mode": is_security_mode,
                # ── Session context vars baru ────────────────────────────────
                "active_session": active_session,
                "viewed_session": viewed_session,
                "all_sessions": all_sessions,
            }
        except Exception:
            return {
                "csp_active": True,
                "rule_detection_active": True,
                "session_status": "none",
                "can_modify": False,
                "is_session_readonly": True,
                # ── Functional RBAC vars baru (fallback) ─────────────────────
                "functional_role": functional_role,
                "mode_label": mode_label,
                "is_simulation_mode": is_simulation_mode,
                "is_security_mode": is_security_mode,
                # ── Session context vars baru (fallback) ─────────────────────
                "active_session": None,
                "viewed_session": None,
                "all_sessions": [],
            }

    # ── Error Handlers ─────────────────────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("errors/500.html"), 500

    # ── Initialize SecuritySetting (buat baris default jika belum ada) ─────────
    with app.app_context():
        try:
            db.create_all()  # buat tabel baru (SecuritySetting, StolenCookie)
            from app.models.security import SecuritySetting
            SecuritySetting.get_settings()  # inisialisasi baris default id=1
        except Exception:
            pass  # jika DB belum siap, abaikan

    return app
