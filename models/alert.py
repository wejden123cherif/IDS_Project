from extensions import db
from datetime import datetime

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(50), default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    attack_type = db.Column(db.String(50), nullable=False)  # 'ARP_KA_SPOOF', 'SYN_FLOOD', etc.
    severity = db.Column(db.String(20), nullable=False)     # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    source_ip = db.Column(db.String(50))
    source_mac = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    details = db.Column(db.Text)
    
    # Store additional metadata if needed
    is_read = db.Column(db.Boolean, default=False)
