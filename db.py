from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Analysis(db.Model):
    __tablename__ = 'analyses'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(255), nullable=False)
    entropy = db.Column(db.Float, nullable=False)
    md5 = db.Column(db.String(32), nullable=False)
    sha1 = db.Column(db.String(40), nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    sha512 = db.Column(db.String(128), nullable=False)
    png_path = db.Column(db.String(255), nullable=False)
    
    cnn_pred = db.Column(db.String(50), nullable=False)
    cnn_conf = db.Column(db.Float, nullable=False)
    
    lstm_pred = db.Column(db.String(50), nullable=False)
    lstm_conf = db.Column(db.Float, nullable=False)
    
    hybrid_pred = db.Column(db.String(50), nullable=False)
    hybrid_conf = db.Column(db.Float, nullable=False)
    
    consensus = db.Column(db.String(50), nullable=False)
    agreement = db.Column(db.Integer, nullable=False)
    verdict = db.Column(db.String(50), nullable=False)
    all_probs_json = db.Column(db.Text, nullable=False)
    ai_report = db.Column(db.Text, nullable=True)
    chat_history_json = db.Column(db.Text, nullable=True)

