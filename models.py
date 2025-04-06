from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

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
    friend1_login = db.Column(db.String(100), db.ForeignKey('user.login'), nullable=False)
    friend2_login = db.Column(db.String(100), db.ForeignKey('user.login'), nullable=False)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)

class Postcard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_login = db.Column(db.String(100), db.ForeignKey('user.login'), nullable=False)
    receiver_login = db.Column(db.String(100), db.ForeignKey('user.login'), nullable=False)
    text = db.Column(db.Text)
    is_private = db.Column(db.Boolean, default=False, nullable=False)
    front_text = db.Column(db.String(200), nullable=False)
    background = db.Column(db.String(100), nullable=False)
    font = db.Column(db.String(100), nullable=False)
    color = db.Column(db.String(50), nullable=False)
    pos_x = db.Column(db.Integer, nullable=False)
    pos_y = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())