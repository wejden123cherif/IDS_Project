from collections import defaultdict, deque
import time

from scapy.layers.inet import IP, TCP
from models.event import SecurityEvent


class SynDetector:
    """Detects potential SYN flood attacks by counting SYN-only packets per source IP

    Simple algorithm:
    - Track timestamps of SYN-only packets per source IP
    - If number of SYNs within WINDOW seconds exceeds THRESHOLD, raise an event
    - Use a cooldown to avoid spamming alerts for the same source
    """

    def __init__(self, window: int = 10, threshold: int = 20, cooldown: int = 30):
        self.window = window
        self.threshold = threshold
        self.cooldown = cooldown  # Reduced from 60 to 30 seconds for better responsiveness
        self.syn_table = defaultdict(deque)  # src_ip -> deque[timestamps]
        self.last_alert = {}  # src_ip -> last alert time
    
    def get_tracking_summary(self):
        """Returns a summary of all IPs being tracked and their packet counts"""
        summary = {}
        now = time.time()
        cutoff = now - self.window
        for src_ip, dq in self.syn_table.items():
            # Clean old timestamps
            while dq and dq[0] < cutoff:
                dq.popleft()
            count = len(dq)
            if count > 0:
                summary[src_ip] = {
                    'count': count,
                    'threshold': self.threshold,
                    'last_alert': self.last_alert.get(src_ip, 0),
                    'time_since_alert': now - self.last_alert.get(src_ip, 0) if src_ip in self.last_alert else None
                }
        return summary

    def process_syn(self, packet):
        if not packet.haslayer(TCP):
            return None

        tcp = packet[TCP]
        # Only consider SYN packets without the ACK flag (SYN-only)
        if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
            return None

        if not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        
        # Extract source MAC address from Ethernet layer if available
        src_mac = None
        if packet.haslayer('Ether'):
            src_mac = packet['Ether'].src
        elif hasattr(packet, 'src'):  # Fallback for other layer types
            try:
                src_mac = packet.src
            except:
                pass
        
        now = time.time()

        dq = self.syn_table[src_ip]
        dq.append(now)

        # Remove old timestamps outside of the window
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

        count = len(dq)

        # Debug logging for SYN packet tracking
        if count > 0 and (count == self.threshold - 1 or count % 10 == 0):  # Log near threshold or every 10 packets
            print(f"[SYN DETECTOR] Tracking {src_ip}: {count}/{self.threshold} SYN packets in {self.window}s window")

        # If threshold exceeded and cooldown elapsed -> raise event
        last = self.last_alert.get(src_ip, 0)
        time_since_last_alert = now - last
        
        if count >= self.threshold:
            if time_since_last_alert >= self.cooldown:
                self.last_alert[src_ip] = now
                print(f"[SYN DETECTOR] SYN Flood detected: {count} SYN packets from {src_ip} in {self.window}s")
                return SecurityEvent(
                    category="SYN Flood",
                    severity="HIGH",
                    message=f"SYN Flood attack detected from {src_ip}: {count} SYN packets in {self.window} seconds",
                    src_ip=src_ip,
                    src_mac=src_mac
                )
            else:
                print(f"[SYN DETECTOR] Threshold exceeded ({count} >= {self.threshold}) but cooldown active. "
                      f"Time remaining: {self.cooldown - time_since_last_alert:.1f}s")

        return None
