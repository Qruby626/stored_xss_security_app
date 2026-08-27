"""
Legacy Authorization Decorators — Backward Compatibility Wrapper

PERUBAHAN: Semua implementasi di-Delegasikan ke Authorization Layer baru
(app.utils.authorization) untuk menerapkan Lightweight Functional RBAC.
File ini TETAP ADA untuk menjaga backward compatibility:
- Import `from app.utils.decorators import admin_required` di 16 routes TIDAK PERLU diubah
- Import `can_modify_object` di forum/comments/chat/announcements TIDAK PERLU diubah

Cukup ubah import jika ingin refactor penuh, tapi saat ini Strategy A: Minimal Change.
"""

from functools import wraps

from flask_login import current_user

from app.utils.authorization import (
    security_analyst_required as _security_analyst_required,
    simulation_required as _simulation_required,
    simulation_read_required as _simulation_read_required,
    can_modify_resource as _can_modify_resource,
)


def admin_required(f):
    """
    Decorator LEGACY — bungkus (wrapper) menuju security_analyst_required baru.
    Digunakan agar route existing yang sudah import @admin_required
    (16 route di security_bp & testing_bp) TIDAK PERLU diubah sama sekali.

    Implementasi 100% diserahkan ke Authorization Layer.
    Lihat: app.utils.authorization.security_analyst_required
    """
    # security_analyst_required sudah handle authentication + functional role check
    # dan juga memberikan flash message semantic baru (tanpa kata 'Administrator').
    return _security_analyst_required(f)


def can_modify_object(obj):
    """
    Ownership-Based Authorization Helper LEGACY — bungkus menuju can_modify_resource.

    Digunakan agar helper existing yang dipakai di routes dan templates
    (forum, comments, announcements, chat) TIDAK PERLU diubah.

    Implementasi 100% diserahkan ke Authorization Layer:
    - Owner object (user_id == current_user.id) BISA memodifikasi.
    - Functional Role SECURITY_ANALYST (legacy: admin) JUGA BISA memodifikasi.

    Lihat: app.utils.authorization.can_modify_resource
    """
    return _can_modify_resource(obj, user=current_user)


def simulation_required(f):
    """
    Decorator proteksi route Simulation Role — wrapper menuju simulation_required di Authorization Layer.

    Digunakan agar import pattern yang sama dengan @admin_required (wrapper layer ini
    untuk konsistensi gaya import di seluruh route Simulation module.

    Implementasi 100% diserahkan ke Authorization Layer.
    Lihat: app.utils.authorization.simulation_required
    """
    return _simulation_required(f)


def simulation_read_required(f):
    """
    Decorator proteksi route READ Simulation — wrapper menuju simulation_read_required di Authorization Layer.

    Digunakan untuk route Simulation yang dapat diakses oleh SIMULATION_ROLE dan SECURITY_ANALYST_ROLE (Admin).
    Implementasi 100% diserahkan ke Authorization Layer.
    Lihat: app.utils.authorization.simulation_read_required
    """
    return _simulation_read_required(f)


__all__ = [
    "admin_required",
    "can_modify_object",
    "simulation_required",
    "simulation_read_required",
]
