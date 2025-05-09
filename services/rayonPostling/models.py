from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    surname = db.Column(db.String(100), nullable=False)
    postcard_signature = db.Column(db.String(200), unique=True, nullable=False)
    notification_token = db.Column(db.String(200), unique=True, nullable=False)

    def get_id(self):
        return str(self.id)


class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    friend1_login = db.Column(
        db.String(100), db.ForeignKey("user.login"), nullable=False
    )
    friend2_login = db.Column(
        db.String(100), db.ForeignKey("user.login"), nullable=False
    )
    is_approved = db.Column(db.Boolean, default=False, nullable=False)

    # Создаем индексы
    __table_args__ = (db.Index("idx_friends_friend2_login_id", "friend2_login", "id"),)


class Postcard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_login = db.Column(
        db.String(100), db.ForeignKey("user.login"), nullable=False
    )
    receiver_login = db.Column(
        db.String(100), db.ForeignKey("user.login"), nullable=False
    )
    text = db.Column(db.Text)
    is_private = db.Column(db.Boolean, default=False, nullable=False)
    image_path = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now, index=True)

    # Создаем индексы
    __table_args__ = (
        db.Index("idx_postcards_receiver_login_id", "receiver_login", "id"),
    )
