from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from pytz import timezone 
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(50), unique=False, nullable=False)
    email = db.Column(db.String(40), unique=True, nullable=True)
    branch = db.Column(db.String(10), nullable=True)
    phone_number = db.Column(db.String(15), unique=True, nullable=True)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='participant')
    video = db.relationship('Video', backref='user', uselist=False)  
    submissions = db.relationship('Submission', backref='user', uselist=False)

    def __init__(self, username, password, role='participant', name=None, email=None, branch=None, phone_number=None):
        self.username = username
        self.password = password
        self.role = role
        self.name = name
        if role == 'participant':
            self.email = email
            self.branch = branch
            self.phone_number = phone_number
        else:
            self.email = None
            self.branch = None
            self.phone_number = None

    def __repr__(self):
        return f'<User {self.username}, Role: {self.role}>'


class Video(db.Model):
    __tablename__ = 'video'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=True)
    filepath = db.Column(db.String(200), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    thumbnail_path = db.Column(db.String(200), nullable=True)
    submission = db.relationship('Submission', backref='video', uselist=False)

    def __repr__(self):
        return f'<Video {self.filename} for User ID {self.user_id}>'


class Submission(db.Model):
    __tablename__ = 'submissions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone("Asia/Kolkata")))
    
    final_creativity = db.Column(db.Float, nullable=False, default=0)
    final_technicality = db.Column(db.Float, nullable=False, default=0)
    final_presentation = db.Column(db.Float, nullable=False, default=0)
    final_score = db.Column(db.Float, nullable=False, default=0)

    scores = db.relationship('Score', backref='submission', lazy=True)

    def __repr__(self):
        return f'<Submission by User {self.user_id} for Video {self.video_id} at {self.timestamp}>'

class SubmissionWindow(db.Model):
    __tablename__ = 'submissionwindow'
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone("Asia/Kolkata")))
    end_time = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone("Asia/Kolkata")))
    
    def __repr__(self):
        return f'<Submission window open from {self.start_time} to {self.end_time}>'


class Judge(db.Model):
    __tablename__ = 'judges'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    
    scores = db.relationship('Score', backref='judge', lazy=True)
    
    def __repr__(self):
        return f'<Judge {self.name}>'


class Score(db.Model):
    __tablename__ = 'scores'
    id = db.Column(db.Integer, primary_key=True)
    creativity = db.Column(db.Integer, nullable=False)
    technicality = db.Column(db.Integer, nullable=False)
    presentation = db.Column(db.Integer, nullable=False)
    total_score = db.Column(db.Integer, nullable=False)
    
    submission_id = db.Column(db.Integer, db.ForeignKey('submissions.id'), nullable=False)
    judge_id = db.Column(db.Integer, db.ForeignKey('judges.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    def __repr__(self):
        return f'<Score {self.total_score} for Submission {self.submission_id} by Judge {self.judge_id}>'
