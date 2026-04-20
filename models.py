from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import hashlib
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    predictions = db.relationship('Prediction', backref='user', lazy=True)

class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    input_data = db.Column(db.Text, nullable=False)
    prediction = db.Column(db.String(100), nullable=False)
    blockchain_hash = db.Column(db.String(64), nullable=False)
    suggestions = db.Column(db.Text, nullable=False)
    prevention_measures = db.Column(db.Text, nullable=False)
    converted_data = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def generate_hash(self):
        """Generate blockchain-like hash for the prediction"""
        data_string = f"{self.input_data}{self.prediction}{self.created_at}"
        return hashlib.sha256(data_string.encode()).hexdigest()
    
    def to_dict(self):
        return {
            'id': self.id,
            'prediction': self.prediction,
            'hash': self.blockchain_hash,
            'suggestions': json.loads(self.suggestions),
            'prevention': json.loads(self.prevention_measures),
            'converted_data': json.loads(self.converted_data) if self.converted_data else None,
            'timestamp': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
    
class SharedMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_email = db.Column(db.String(120), nullable=False)
    message_content = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(500), nullable=True)
    file_name = db.Column(db.String(255), nullable=True)
    file_size = db.Column(db.Integer, default=0)
    is_anomaly = db.Column(db.Boolean, default=False)
    anomaly_score = db.Column(db.Float, default=0.0)
    anomaly_type = db.Column(db.String(100), nullable=True)
    blockchain_hash = db.Column(db.String(64), nullable=True)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    sender = db.relationship('User', backref='sent_messages', foreign_keys=[sender_id])

class SharedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('shared_message.id'), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(100), nullable=True)
    file_size = db.Column(db.Integer, default=0)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    message = db.relationship('SharedMessage', backref='files')