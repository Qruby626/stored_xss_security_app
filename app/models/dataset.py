from datetime import datetime
from app import db


class PayloadDataset(db.Model):
    """Dataset payload Stored XSS dari Lampiran A skripsi penelitian."""
    __tablename__ = "payload_dataset"

    id = db.Column(db.Integer, primary_key=True)
    kode_payload = db.Column(db.String(20), nullable=False, unique=True)
    payload = db.Column(db.Text, nullable=False)
    kategori = db.Column(db.String(100), nullable=False)
    sumber = db.Column(db.String(100), nullable=False)
    deskripsi = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f"<PayloadDataset {self.kode_payload} [{self.kategori}]>"
