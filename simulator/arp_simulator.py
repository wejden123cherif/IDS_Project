from scapy.all import ARP, send, get_if_hwaddr, conf
import time
import sys
import os

# Ensure project root is on sys.path so "app" and "models" can be imported
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def _create_db_alert(attack_type, severity, source_ip=None, source_mac=None, destination_ip=None, details=""):
    """
    Helper used only by the simulator to ensure an Alert row is created
    even if the live sniffer does not capture the packets.
    """
    try:
        from app import app, db   # Import the Flask app and database
        from models.alert import Alert

        with app.app_context():
            alert = Alert(
                attack_type=attack_type,
                severity=severity,
                source_ip=source_ip,
                source_mac=source_mac,
                destination_ip=destination_ip,
                details=details or f"Simulated {attack_type} attack"
            )
            db.session.add(alert)
            db.session.commit()
            print(f"[SIM] Alert saved to database with ID={alert.id}")
    except Exception as e:
        print(f"[SIM] WARNING: Failed to create alert in database: {e}")

def simulate_arp_spoof(target_ip="192.168.1.1", gateway_ip="192.168.1.254"):
    """
    Simulates ARP spoofing by sending ARP replies with conflicting MAC addresses.
    """
    print(f"[*] Starting ARP Spoof Simulation...")
    print(f"[*] Target: {target_ip}")
    print(f"[*] Gateway IP (spoofed): {gateway_ip}")
    
    # 1. Send normal packet first
    try:
        my_mac = get_if_hwaddr(conf.iface)
    except:
        my_mac = "00:11:22:33:44:55"
        
    print(f"[*] Phase 1: Sending legitimate ARP reply from {my_mac}")
    pkt1 = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc=my_mac, hwdst="ff:ff:ff:ff:ff:ff")
    send(pkt1, verbose=False)
    time.sleep(1.5)
    
    # 2. Send conflicting packet
    fake_mac = "AA:BB:CC:DD:EE:FF"
    print(f"[*] Phase 2: Sending SPOOFED ARP reply from {fake_mac}")
    pkt2 = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc=fake_mac, hwdst="ff:ff:ff:ff:ff:ff")
    send(pkt2, verbose=False)
    time.sleep(0.5)
    
    print("[*] Spoofed packets sent!")

    # Direct DB Insert (Simulating reliable detection)
    _create_db_alert(
        attack_type="ARP Spoofing (Simulation)",
        severity="HIGH",
        source_ip=gateway_ip,
        source_mac=fake_mac,
        destination_ip=target_ip,
        details=f"Simulated ARP spoofing attack: {gateway_ip} -> {target_ip}, MAC {my_mac} -> {fake_mac}"
    )

    print("[*] Check the dashboard for 'ARP Spoofing' alert!")

if __name__ == "__main__":
    try:
        simulate_arp_spoof()
    except PermissionError:
        print("[!] Error: You need to run this as Administrator/Root to send packets.")
    except Exception as e:
        print(f"[!] Error: {e}")
