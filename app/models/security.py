from datetime import datetime
from app import db


class TestSession(db.Model):
    """Stores a single XSS testing scenario (Simple Test Session Management)."""
    __tablename__ = "test_sessions"

    id = db.Column(db.Integer, primary_key=True)
    session_name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    started_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    ended_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), nullable=False, default="active")  # active | finished
    is_legacy = db.Column(db.Boolean, default=False, nullable=False)

    security_logs = db.relationship("SecurityLog", backref="test_session", cascade="all, delete-orphan")
    csp_reports = db.relationship("CspReport", backref="test_session", cascade="all, delete-orphan")
    forum_posts = db.relationship("ForumPost", backref="test_session", cascade="all, delete-orphan")
    comments = db.relationship("Comment", backref="test_session", cascade="all, delete-orphan")
    announcements = db.relationship("Announcement", backref="test_session", cascade="all, delete-orphan")
    chat_messages = db.relationship("ChatMessage", backref="test_session", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<TestSession {self.id} [{self.status}] {self.session_name}>"


class SecurityLog(db.Model):
    """Stores results of Rule-Based XSS Detection for each user input."""
    __tablename__ = "security_logs"

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(
        db.Integer, db.ForeignKey("test_sessions.id"), nullable=False, index=True
    )
    source_feature = db.Column(db.String(50), nullable=False)   # forum|comment|announcement|chat
    payload = db.Column(db.Text, nullable=False)
    matched_rule = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), nullable=False, default="SAFE")  # DETECTED | SAFE
    created_at = db.Column(db.DateTime, default=datetime.now)
    submission_id = db.Column(db.String(36), nullable=True)  # UUID for grouping payload submissions
    object_type = db.Column(db.String(50), nullable=True, index=True)  # forum_post|comment|announcement|chat_message
    object_id = db.Column(db.Integer, nullable=True, index=True)

    def __repr__(self):
        return f"<SecurityLog {self.id} [{self.status}] {self.source_feature}>"


class CspReport(db.Model):
    """Stores CSP violation reports sent by the browser."""
    __tablename__ = "csp_reports"

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(
        db.Integer, db.ForeignKey("test_sessions.id"), nullable=False, index=True
    )
    submission_id = db.Column(db.String(36), nullable=True, index=True)
    document_uri = db.Column(db.String(500), nullable=True)
    violated_directive = db.Column(db.String(255), nullable=True)
    blocked_uri = db.Column(db.String(500), nullable=True)
    original_policy = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f"<CspReport {self.id} {self.violated_directive}>"


class SecuritySetting(db.Model):
    """Stores global on/off toggle flags for the Security Engine.
    Only one row should ever exist (id=1); use get_settings() to retrieve it.
    """
    __tablename__ = "security_settings"

    id = db.Column(db.Integer, primary_key=True)
    rule_detection_enabled = db.Column(db.Boolean, nullable=False, default=True)
    csp_nonce_enabled = db.Column(db.Boolean, nullable=False, default=True)

    @classmethod
    def get_settings(cls):
        """Return the single settings row, creating it if absent."""
        row = cls.query.get(1)
        if row is None:
            row = cls(id=1, rule_detection_enabled=True, csp_nonce_enabled=True)
            db.session.add(row)
            db.session.commit()
        return row

    def __repr__(self):
        return (
            f"<SecuritySetting rule={self.rule_detection_enabled} "
            f"csp={self.csp_nonce_enabled}>"
        )


class StolenCookie(db.Model):
    """Stores cookie data captured by the Local Attacker Listener endpoint.
    Used as empirical evidence of Session Hijacking via stored XSS.
    """
    __tablename__ = "stolen_cookies"

    id = db.Column(db.Integer, primary_key=True)
    cookie_value = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(50), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f"<StolenCookie {self.id} from {self.ip_address}>"
