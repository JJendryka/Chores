from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nick = db.Column(db.String(60), unique=True)
    password = db.Column(db.Text, nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False)
    counters = db.relationship('Counter', backref='user', lazy=True)

class Chore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), unique=True, nullable=False)
    period_of_days = db.Column(db.Integer, nullable=False)
    cooldown_time = db.Column(db.Integer)
    minimum_point = db.Column(db.Integer)
    counters = db.relationship('Counter', backref='chore', lazy=True)

class Counter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.Integer, nullable=False)
    multiplier = db.Column(db.Float)
    chore_id = db.Column(db.Integer, db.ForeignKey('chore.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)