import os
import threading
import time
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from extensions import db, login_manager
from models.user import User
from models.alert import Alert

# Sniffing & detectors
from sniffing.packet_sniffer import PacketCapture
from sniffing import arp_detector
from sniffing.syn_detector import SynDetector

from queue import Empty
from scapy.all import ARP

# -------------------- Flask App --------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-prod'

db_path = os.path.join(os.path.dirname(__file__), 'database', 'vuln_app.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

# -------------------- Global State --------------------
monitoring_status = False

stats = {
    'total_packets': 0,
    'arp_packets': 0,
    'tcp_packets': 0,
    'syn_packets': 0,
    'alerts_triggered': 0
}

config = {
    'SYN_FLOOD_THRESHOLD': 20,
    'SYN_FLOOD_TIME_WINDOW': 10,
    'ARP_FLOOD_THRESHOLD': 30,
    'ARP_FLOOD_TIME_WINDOW': 5
}

# -------------------- Background Sniffer --------------------
class BackgroundSniffer:
    def __init__(self):
        self.stop_signal = threading.Event()
        self.is_running = False

        self.arp_table = {}
        self.syn_detector = SynDetector()
        self.capture = PacketCapture(test_mode=True)

        self._update_detector_config()

    def _update_detector_config(self):
        self.syn_detector.threshold = config['SYN_FLOOD_THRESHOLD']
        self.syn_detector.window = config['SYN_FLOOD_TIME_WINDOW']
        arp_detector.ARP_FLOOD_THRESHOLD = config['ARP_FLOOD_THRESHOLD']
        arp_detector.ARP_FLOOD_TIME_WINDOW = config['ARP_FLOOD_TIME_WINDOW']

    def start(self, interface=None):
        if self.is_running:
            return False

        self.stop_signal.clear()
        self._update_detector_config()

        # Reset detectors
        self.arp_table.clear()
        arp_detector.alerted_spoof.clear()
        arp_detector.alerted_flood.clear()
        arp_detector.arp_rate.clear()
        self.syn_detector.syn_table.clear()
        self.syn_detector.last_alert.clear()

        self.capture.stop_capture.clear()
        self.capture.start_capture(interface)

        threading.Thread(target=self._process_packets, daemon=True).start()
        self.is_running = True
        return True

    def stop(self):
        self.stop_signal.set()
        self.capture.stop()
        self.is_running = False

    # 🔥 BRIDGE METHOD
    def raise_alert(self, evt, packet=None):
        self._trigger_alert(evt, packet)

    def _process_packets(self):
        print("[*] Packet processing thread started")

        with app.app_context():
            q = self.capture.packet_queue

            while not self.stop_signal.is_set():
                try:
                    packet = q.get(timeout=1)
                    stats['total_packets'] += 1

                    # -------------------- ARP --------------------
                    if packet.haslayer(ARP):
                        stats['arp_packets'] += 1

                        arp_detector.process_arp(
                            packet,
                            self.arp_table,
                            lambda evt: self.raise_alert(evt, packet)
                        )

                    # -------------------- TCP / SYN --------------------
                    elif packet.haslayer('IP') and packet.haslayer('TCP'):
                        stats['tcp_packets'] += 1
                        tcp = packet['TCP']

                        if tcp.flags & 0x02:
                            stats['syn_packets'] += 1

                        if tcp.flags & 0x02 and not (tcp.flags & 0x10):
                            evt = self.syn_detector.process_syn(packet)
                            if evt:
                                self._trigger_alert(evt, packet)

                except Empty:
                    continue
                except Exception as e:
                    print(f"[!] Error processing packet: {e}")
                    import traceback
                    traceback.print_exc()

    def _trigger_alert(self, evt, packet=None):
        stats['alerts_triggered'] += 1

        print("\n" + "=" * 60)
        print(f"[!] ALERT: {evt.category}")
        print(f"[!] Severity: {evt.severity}")
        print(f"[!] Message: {evt.message}")
        print(f"[!] Source IP: {evt.src_ip}")
        print("=" * 60 + "\n")

        destination_ip = None
        if packet:
            if packet.haslayer(ARP):
                destination_ip = packet[ARP].pdst
            elif packet.haslayer('IP'):
                destination_ip = packet['IP'].dst

        try:
            alert = Alert(
                attack_type=evt.category,
                severity=evt.severity,
                # message removed (not in model)
                source_ip=evt.src_ip,
                source_mac=evt.src_mac,
                destination_ip=destination_ip,
                details=evt.message
            )
            db.session.add(alert)
            db.session.commit()
        except Exception as e:
            print(f"[!] DB error: {e}")
            db.session.rollback()

# -------------------- Init --------------------
global_sniffer = BackgroundSniffer()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------- Routes --------------------
@app.route('/')
def index():
    return redirect(url_for('dashboard')) if current_user.is_authenticated else redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    alerts = Alert.query.order_by(Alert.id.desc()).limit(10).all()
    stats['alerts_triggered'] = Alert.query.count()
    return render_template(
        'dashboard.html',
        monitoring_status=global_sniffer.is_running,
        stats=stats,
        alerts=alerts
    )

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
        
    latest_alerts = Alert.query.order_by(Alert.id.desc()).limit(50).all()
    users = User.query.all()
    stats['alerts_triggered'] = Alert.query.count()
    
    return render_template('admin.html',
                           monitoring_status=global_sniffer.is_running,
                           config=config,
                           stats=stats,
                           alerts=latest_alerts,
                           users=users)


@app.route('/api/interfaces', methods=['GET'])
@login_required
def get_interfaces_api():
    """Return available network interfaces using Scapy's get_if_list()."""
    try:
        from scapy.all import get_if_list
        ifaces = get_if_list()
        return jsonify({'success': True, 'interfaces': ifaces})
    except Exception as e:
        return jsonify({'success': False, 'interfaces': [], 'error': str(e)})

# -------------------- API --------------------
@app.route('/api/monitoring/start', methods=['POST'])
@login_required
def start_monitoring():
    if not current_user.is_admin:
        return jsonify({'success': False}), 403

    data = request.json or {}
    iface = data.get('interface')

    if global_sniffer.start(iface):
        return jsonify({'success': True})
    return jsonify({'success': False})

@app.route('/api/monitoring/stop', methods=['POST'])
@login_required
def stop_monitoring():
    if not current_user.is_admin:
        return jsonify({'success': False}), 403

    global_sniffer.stop()
    return jsonify({'success': True})

@app.route('/api/monitoring/status')
@login_required
def api_status():
    global monitoring_status
    if hasattr(global_sniffer, 'is_running'):
        monitoring_status = global_sniffer.is_running
    
    # Sync alerts_triggered with DB count to ensure accuracy
    try:
        stats['alerts_triggered'] = Alert.query.count()
    except Exception:
        pass
    
    return jsonify({
        'is_running': monitoring_status,
        'statistics': stats
    })

@app.route('/api/alerts')
@login_required
def get_alerts():
    alerts = Alert.query.order_by(Alert.id.desc()).limit(20).all()
    return jsonify([
        {
            'id': a.id,
            'attack_type': a.attack_type,
            'severity': a.severity,
            'source_ip': a.source_ip,
            'destination_ip': a.destination_ip,
            'details': a.details
        } for a in alerts
    ]) 

@app.route('/api/sim/notify', methods=['POST'])
def api_sim_notify():
    """
    Local simulator notification endpoint. Accepts JSON describing a simulated alert
    and creates the Alert row in the running Flask process so in-memory `stats` is updated.
    """
    remote = request.remote_addr
    if remote not in ("127.0.0.1", "::1", "localhost"):
        return jsonify({'success': False, 'error': 'Forbidden'}), 403

    data = request.get_json(silent=True) or {}
    attack_type = data.get('attack_type', 'Simulation')
    severity = data.get('severity', 'LOW')
    source_ip = data.get('source_ip')
    source_mac = data.get('source_mac')
    destination_ip = data.get('destination_ip')
    details = data.get('details', '')

    try:
        alert = Alert(
            attack_type=attack_type,
            severity=severity,
            # message=details or attack_type,  <-- REMOVED (field does not exist in model)
            source_ip=source_ip,
            source_mac=source_mac,
            destination_ip=destination_ip,
            details=details or attack_type
        )
        db.session.add(alert)
        db.session.commit()
        try:
            stats['alerts_triggered'] = Alert.query.count()
        except Exception:
            stats['alerts_triggered'] = stats.get('alerts_triggered', 0) + 1
        return jsonify({'success': True, 'id': alert.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/config/update', methods=['POST'])
@login_required
def update_config():
     if not current_user.is_admin:
         return jsonify({'success': False, 'message': 'Admin privilege required'}), 403
     
     data = request.json
     if data:
         config['SYN_FLOOD_THRESHOLD'] = int(data.get('syn_threshold', config['SYN_FLOOD_THRESHOLD']))
         config['SYN_FLOOD_TIME_WINDOW'] = int(data.get('time_window', config['SYN_FLOOD_TIME_WINDOW']))
         config['ARP_FLOOD_THRESHOLD'] = int(data.get('arp_threshold', config.get('ARP_FLOOD_THRESHOLD', 30)))
         config['ARP_FLOOD_TIME_WINDOW'] = int(data.get('arp_time_window', config.get('ARP_FLOOD_TIME_WINDOW', 5)))
         # Update detectors immediately
         global_sniffer._update_detector_config()
     return jsonify({'success': True, 'message': 'Configuration updated'})

# -------------------- DB Init --------------------
def init_db():
    with app.app_context():
        os.makedirs(os.path.join(os.path.dirname(__file__), 'database'), exist_ok=True)
        db.create_all()

        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@test.com', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)

        if not User.query.filter_by(username='user').first():
            user = User(username='user', email='user@test.com', is_admin=False)
            user.set_password('user123')
            db.session.add(user)

        db.session.commit()

# -------------------- Main --------------------
if __name__ == '__main__':
    init_db()
    print("[*] IDS started at http://127.0.0.1:5000")
    app.run(debug=True, use_reloader=False)
