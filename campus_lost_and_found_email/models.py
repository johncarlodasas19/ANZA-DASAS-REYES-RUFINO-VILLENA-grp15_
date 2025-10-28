from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20))  # lost/found
    name = db.Column(db.String(200))
    description = db.Column(db.Text)
    location = db.Column(db.String(200))
    photo = db.Column(db.String(300))
    phash = db.Column(db.String(200))
    status = db.Column(db.String(50), default='open')  # open, pending_claim, returned, unresolved, deleted
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    claimed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
