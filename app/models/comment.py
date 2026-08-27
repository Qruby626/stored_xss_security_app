from datetime import datetime
from app import db


class Comment(db.Model):
    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(
        db.Integer, db.ForeignKey("test_sessions.id"), nullable=True, index=True
    )
    content = db.Column(db.Text, nullable=False)
    post_id = db.Column(
        db.Integer,
        db.ForeignKey("forum_posts.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

    # Relationships
    post = db.relationship(
        "ForumPost",
        backref=db.backref(
            "comments",
            lazy="dynamic",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
    )

    def __repr__(self):
        return f"<Comment {self.id} on Post {self.post_id}>"
