"""
Lightweight Functional Role-Based Access Control (Functional RBAC)
Authorization Layer — Single Source of Truth

Arsitektur:
    Research User (Login)
        → Database Role [admin | student]
            → Translasi Layer (resolve_functional_role)
                → Functional Role [SIMULATION_ROLE | SECURITY_ANALYST_ROLE]
                    → Decorator / Helper authorization

PRINSIP:
- Authorization terpusat di file ini. JANGAN ada pengecekan role == 'admin' / 'student'
  langsung di route, template, atau blueprint lain.
- Tidak mengubah struktur database & isi tabel users (tetap pakai admin/student).
- Translasi hanya dilakukan di Authorization Layer ini saja.

Modules Access Matrix (Target Functional RBAC):
    SIMULATION_ROLE         → forum, comments, announcements, chat, dashboard
    SECURITY_ANALYST_ROLE   → security dashboard, logs, reports, statistics,
                               testing/experiment dataset, session management
"""

from functools import wraps
from typing import Optional

from flask import redirect, url_for, flash
from flask_login import current_user


# ── Functional Role Constants ──────────────────────────────────────────────────
SIMULATION_ROLE = "simulation"
SECURITY_ANALYST_ROLE = "security_analyst"
UNKNOWN_ROLE = "unknown"

# ── UI Label Constants ─────────────────────────────────────────────────────────
MODE_LABEL_SIMULATION = "Student"
MODE_LABEL_SECURITY = "Admin"
MODE_LABEL_UNKNOWN = "Mode Tidak Dikenali"

# ── Legacy DB Role → Functional Role Mapping ───────────────────────────────────
_DB_TO_FUNCTIONAL = {
    "admin": SECURITY_ANALYST_ROLE,
    "student": SIMULATION_ROLE,
}

# ── Module → Functional Role Access Matrix ─────────────────────────────────────
# Untuk dokumentasi & programmatic check jika dibutuhkan di kemudian hari.
MODULE_ACCESS_MATRIX = {
    # Simulation modules
    "dashboard": SIMULATION_ROLE,
    "forum": SIMULATION_ROLE,
    "comments": SIMULATION_ROLE,
    "announcements": SIMULATION_ROLE,
    "chat": SIMULATION_ROLE,
    # Security / Analyst modules
    "security": SECURITY_ANALYST_ROLE,
    "testing": SECURITY_ANALYST_ROLE,
    # Auth module (public)
    "auth": None,
}


# ── Core Translasi Layer ───────────────────────────────────────────────────────
def resolve_functional_role(db_role: Optional[str]) -> str:
    """
    Translasikan nilai role legacy dari database ke Functional Role modern.
    Tidak mengubah database — hanya translasi di Application Layer.

    Args:
        db_role: Nilai kolom `users.role` dari DB (string 'admin' | 'student').

    Returns:
        Salah satu konstanta: SIMULATION_ROLE | SECURITY_ANALYST_ROLE | UNKNOWN_ROLE
    """
    if not db_role:
        return UNKNOWN_ROLE
    normalized = str(db_role).strip().lower()
    return _DB_TO_FUNCTIONAL.get(normalized, UNKNOWN_ROLE)


def get_functional_role(user=None) -> str:
    """
    Dapatkan Functional Role dari Flask-Login current_user.

    Args:
        user: Instance User (opsional). Default = current_user dari Flask-Login.

    Returns:
        Konstanta Functional Role string.
    """
    u = user if user is not None else current_user
    if not u or not getattr(u, "is_authenticated", False):
        return UNKNOWN_ROLE
    db_role = getattr(u, "role", None)
    return resolve_functional_role(db_role)


# ── Functional Role Check Predicates ───────────────────────────────────────────
def is_simulation_role(user=None) -> bool:
    """Return True jika user (default current_user) memiliki Functional Role Simulation."""
    return get_functional_role(user) == SIMULATION_ROLE


def is_security_analyst_role(user=None) -> bool:
    """Return True jika user (default current_user) memiliki Functional Role Security Analyst."""
    return get_functional_role(user) == SECURITY_ANALYST_ROLE


def can_access_module(module_name: str, user=None) -> bool:
    """
    Periksa apakah Functional Role saat ini diizinkan mengakses modul (blueprint) tertentu.

    Args:
        module_name: Nama blueprint (key dari MODULE_ACCESS_MATRIX).
        user: Instance User (opsional).

    Returns:
        bool: True jika diizinkan atau modul bersifat publik (None).
    """
    required_role = MODULE_ACCESS_MATRIX.get(module_name)
    if required_role is None:
        return True
    return get_functional_role(user) == required_role


# ── UI Label Helper ────────────────────────────────────────────────────────────
def get_mode_label(functional_role: Optional[str] = None) -> str:
    """
    Dapatkan label teks Role untuk ditampilkan di UI.

    Args:
        functional_role: Nilai Functional Role. Jika None, ambil dari current_user.

    Returns:
        Label "Student" / "Admin" / "Mode Tidak Dikenali".
    """
    if functional_role is None:
        functional_role = get_functional_role()
    if functional_role == SIMULATION_ROLE:
        return MODE_LABEL_SIMULATION
    if functional_role == SECURITY_ANALYST_ROLE:
        return MODE_LABEL_SECURITY
    return MODE_LABEL_UNKNOWN


# ── Default Dashboard Redirect Helper ──────────────────────────────────────────
def get_default_dashboard_endpoint(user=None) -> str:
    """
    Single Source of Truth: endpoint default dashboard setelah login / redirect root.

    Mode TIDAK dipilih user — ditentukan OTOMATIS berdasarkan Functional Role:
    - Simulation User    → "dashboard.index"  (Dashboard Simulasi)
    - Security Analyst   → "security.dashboard"  (Security Dashboard)
    - Unknown / Belum login → fallback ke "dashboard.index" (akan di-redirect ke login)

    Returns:
        Nama endpoint Flask untuk digunakan di url_for(...).
    """
    functional_role = get_functional_role(user)
    if functional_role == SECURITY_ANALYST_ROLE:
        return "security.dashboard"
    return "dashboard.index"


def get_default_dashboard_url(user=None) -> str:
    """
    Build URL default dashboard berdasarkan Functional Role.

    Memakai get_default_dashboard_endpoint() sebagai SSOT mapping role → endpoint.
    """
    from flask import url_for
    endpoint = get_default_dashboard_endpoint(user)
    return url_for(endpoint)


# ── Ownership + Role Based Modify Helper ───────────────────────────────────────
def can_modify_resource(obj, user=None) -> bool:
    """
    Single Source of Truth pengecekan hak modifikasi objek data.

    Izin diberikan JIKA salah satu terpenuhi:
        1. User adalah PEMILIK objek (obj.user_id == current_user.id)
        2. User memiliki Functional Role SECURITY_ANALYST_ROLE (setara admin)

    Args:
        obj: Objek data dengan atribut user_id (ForumPost, Comment, ChatMessage, Announcement, dst).
        user: Instance User (opsional, default current_user).

    Returns:
        bool: True jika user dapat mengedit/menghapus objek.
    """
    u = user if user is not None else current_user
    if not u or not getattr(u, "is_authenticated", False):
        return False
    # Owner check
    owner_id = getattr(obj, "user_id", None)
    if owner_id is not None and owner_id == getattr(u, "id", None):
        return True
    # Security Analyst bypass (previously: role == "admin")
    return is_security_analyst_role(u)


# ── Authorization Decorators ───────────────────────────────────────────────────
def security_analyst_required(f):
    """
    Decorator proteksi route — hanya dapat diakses oleh Functional Role Security Analyst.
    Pengganti semantic untuk @admin_required.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Silakan login terlebih dahulu.", "warning")
            return redirect(url_for("auth.login"))
        if not is_security_analyst_role():
            flash(
                "Akses ditolak. Anda berada pada role Student. "
                "Fitur ini hanya tersedia untuk role Admin.",
                "danger",
            )
            return redirect(url_for("dashboard.index"))
        return f(*args, **kwargs)
    return decorated_function


def simulation_required(f):
    """
    Decorator proteksi route — hanya dapat diakses oleh Functional Role Simulation.
    (Untuk proteksi rute Simulation Role jika diperlukan nanti.)
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Silakan login terlebih dahulu.", "warning")
            return redirect(url_for("auth.login"))
        if not is_simulation_role():
            flash(
                "Akses ditolak. Anda berada pada role Admin. "
                "Fitur ini hanya tersedia untuk role Student.",
                "danger",
            )
            return redirect(url_for("security.dashboard"))
        return f(*args, **kwargs)
    return decorated_function


def simulation_read_required(f):
    """
    Decorator proteksi route READ Simulation — dapat diakses oleh Simulation Role dan Security Analyst Role.
    
    Izin diberikan JIKA salah satu terpenuhi:
        1. User memiliki Functional Role SIMULATION_ROLE (full access)
        2. User memiliki Functional Role SECURITY_ANALYST_ROLE (read-only access)
    
    Tujuan: Admin (Security Analyst) dapat melihat data Simulation tetapi tidak dapat WRITE.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Silakan login terlebih dahulu.", "warning")
            return redirect(url_for("auth.login"))
        # Izinkan SIMULATION_ROLE dan SECURITY_ANALYST_ROLE untuk READ
        if not (is_simulation_role() or is_security_analyst_role()):
            flash(
                "Akses ditolak. Anda tidak memiliki izin untuk mengakses fitur ini.",
                "danger",
            )
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated_function


# ── Exports Public API ─────────────────────────────────────────────────────────
__all__ = [
    # Constants
    "SIMULATION_ROLE",
    "SECURITY_ANALYST_ROLE",
    "UNKNOWN_ROLE",
    "MODE_LABEL_SIMULATION",
    "MODE_LABEL_SECURITY",
    "MODULE_ACCESS_MATRIX",
    # Core Translasi
    "resolve_functional_role",
    "get_functional_role",
    # Predicates
    "is_simulation_role",
    "is_security_analyst_role",
    "can_access_module",
    # UI
    "get_mode_label",
    # Default Dashboard SSOT
    "get_default_dashboard_endpoint",
    "get_default_dashboard_url",
    # Modify
    "can_modify_resource",
    # Decorators
    "security_analyst_required",
    "simulation_required",
    "simulation_read_required",
]
