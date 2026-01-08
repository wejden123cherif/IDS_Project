from scapy.all import ARP, send, conf
import time
import random

def simulate_arp_flood(count=50):
    """
    Simulates ARP flooding by sending many ARP requests in a short time.
    Uses a FIXED source IP to ensure threshold is reached for detection.
    """
    print(f"[*] Starting ARP Flood Simulation...")
    print(f"[*] Sending {count} ARP packets rapidly...")
    
    # Use a FIXED source IP to trigger the per-IP flood detector
    # The detector tracks packets per source IP, so we need many from same IP
    src_ip = "192.168.1.100"  # Fixed source IP
    target_ip = "192.168.1.1"  # Common target
    
    print(f"[*] Simulating attack from single source: {src_ip}")
    print(f"[*] Target: {target_ip}")
    print(f"[*] Threshold: 30 packets in 5 seconds (will trigger with {count} packets)")
    
    for i in range(count):
        # Send ARP requests from the same source IP
        pkt = ARP(op=1, pdst=target_ip, psrc=src_ip)
        send(pkt, verbose=False)
        
        if (i + 1) % 10 == 0:
            print(f"  [*] Sent {i+1}/{count} packets...")
        
        # Send very fast to exceed threshold within time window
        time.sleep(0.01)  # 0.01s = 100 packets/second, well above threshold
        
    print(f"[*] Sent {count} packets from {src_ip}.")
    print("[*] Check dashboard for 'ARP Flooding' alert/stats.")
    print("[*] Alert should appear in the 'All Security Alerts' table within 5 seconds.")

    # Notify running Flask app so its in-memory stats are updated immediately
    try:
        import json, urllib.request
        payload = {
            'attack_type': 'ARP Flooding (Simulation)',
            'severity': 'MEDIUM',
            'source_ip': src_ip,
            'source_mac': None,
            'destination_ip': target_ip,
            'details': f"Simulated ARP flood: {count} ARP packets from {src_ip} to {target_ip}"
        }
        req = urllib.request.Request(
            'http://127.0.0.1:5000/api/sim/notify',
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            body = resp.read().decode('utf-8')
            print(f"[SIM] Notified Flask app: {body}")
    except Exception as e:
        print(f"[SIM] Warning: could not notify Flask app: {e}")

if __name__ == "__main__":
    try:
        simulate_arp_flood()
    except PermissionError:
        print("[!] Error: You need to run this as Administrator/Root to send packets.")
