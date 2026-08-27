from flask import Blueprint, render_template, request
from flask_login import login_required
from app.utils.decorators import admin_required
from app.models.dataset import PayloadDataset
from app.utils.detection_pattern_helper import get_detection_patterns

testing_bp = Blueprint("testing", __name__, template_folder="../../templates/testing")

KATEGORI_LIST = [
    "Inline Script Injection",
    "Event Handler Injection",
    "Cookie Theft",
    "DOM Manipulation",
]

PER_PAGE = 10


@testing_bp.route("/")
@login_required
@admin_required
def index():
    search = request.args.get("search", "").strip()
    kategori_filter = request.args.get("kategori", "").strip()
    page = request.args.get("page", 1, type=int)

    query = PayloadDataset.query

    if search:
        like = f"%{search}%"
        query = query.filter(
            PayloadDataset.payload.ilike(like)
            | PayloadDataset.kode_payload.ilike(like)
            | PayloadDataset.deskripsi.ilike(like)
        )

    if kategori_filter and kategori_filter in KATEGORI_LIST:
        query = query.filter(PayloadDataset.kategori == kategori_filter)

    pagination = query.order_by(PayloadDataset.id.asc()).paginate(
        page=page, per_page=PER_PAGE, error_out=False
    )

    # Statistik per kategori
    stats = {}
    for kat in KATEGORI_LIST:
        stats[kat] = PayloadDataset.query.filter_by(kategori=kat).count()
    total = PayloadDataset.query.count()

    patterns = get_detection_patterns()
    return render_template(
        "testing/index.html",
        payloads=pagination.items,
        pagination=pagination,
        search=search,
        kategori_filter=kategori_filter,
        kategori_list=KATEGORI_LIST,
        stats=stats,
        total=total,
        patterns=patterns,
    )
