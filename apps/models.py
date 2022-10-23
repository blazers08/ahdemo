"""table schema"""
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from datetime import datetime

db = SQLAlchemy()
ma = Marshmallow()

class Users(db.Model):
  __tablename__ = 'users'
  id = db.Column(db.Integer, primary_key=True)
  email = db.Column(db.String(200), nullable=False, unique=True)
  password = db.Column(db.String(200))
  name = db.Column(db.String(200))
  sign_up_time = db.Column(db.DateTime, default=datetime.utcnow)
  logged_in_times = db.Column(db.Integer, default=0)
