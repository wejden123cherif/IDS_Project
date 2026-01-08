from collections import defaultdict
from datetime import datetime
import time
from scapy.all import ARP
from models.event import SecurityEvent

# ---- ARP rate tracking (for flooding detection)
arp_rate = defaultdict(list)   # IP -> list of timestamps

# ---- Already-alerted IPs (prevents duplicate alerts)
alerted_spoof = set()
alerted_flood = set()

# ---- Configurable thresholds (can be updated from admin panel)
ARP_FLOOD_THRESHOLD = 30
ARP_FLOOD_TIME_WINDOW = 5


def process_arp(packet, arp_table):
    """
    Processes an ARP packet and detects:
    - ARP spoofing (MAC address changes for same IP)
    - ARP flooding (high ARP rate in short time)

    Returns a SecurityEvent if an attack is detected; otherwise None.
    """

    if not packet.haslayer(ARP):
        return None

    arp = packet["ARP"]
    
    # Only process ARP replies (op=2) for spoofing detection
    # ARP requests (op=1) are normal and don't indicate spoofing
    if int(arp.op) != 2:
        # Still track for flooding detection
        ip = arp.psrc
        mac = arp.hwsrc
        now = time.time()
        
        # Track for flooding
        arp_rate[ip].append(now)
        WINDOW = ARP_FLOOD_TIME_WINDOW
        THRESHOLD = ARP_FLOOD_THRESHOLD
        arp_rate[ip] = [t for t in arp_rate[ip] if now - t <= WINDOW]
        
        if len(arp_rate[ip]) > THRESHOLD and ip not in alerted_flood:
            alerted_flood.add(ip)
            return SecurityEvent(
                category="ARP Flooding",
                severity="MEDIUM",
                message=(
                    f"ARP flooding detected from {ip} | "
                    f"{len(arp_rate[ip])} ARP packets in {WINDOW}s"
                ),
                src_ip=ip,
                src_mac=mac
            )
        return None
    
    ip = arp.psrc
    mac = arp.hwsrc
    dst_ip = arp.pdst

    now = time.time()

    # ==================================================
    # 1️⃣ ARP SPOOFING DETECTION (Improved)
    # ==================================================
    # Check if IP already exists in our table with different MAC
    if ip in arp_table:
        stored_mac = arp_table[ip]
        if stored_mac != mac:
            # MAC address changed - possible ARP spoofing!
            print(f"[ARP DETECTOR] MAC address change detected for {ip}: {stored_mac} -> {mac}")
            if ip not in alerted_spoof:
                alerted_spoof.add(ip)
                # Calculate severity
                severity = "HIGH"
                try:
                    from scapy.all import conf
                    gateway_ip = conf.route.route("0.0.0.0")[2]
                    if ip == gateway_ip:
                        severity = "CRITICAL"
                        print(f"[ARP DETECTOR] CRITICAL: Gateway IP spoofing detected!")
                except:
                    pass
                
                print(f"[ARP DETECTOR] ARP Spoofing alert triggered for {ip}")
                return SecurityEvent(
                    category="ARP Spoofing",
                    severity=severity,
                    message=(
                        f"ARP spoofing detected for {ip} | "
                        f"MAC address changed from {stored_mac} to {mac}. "
                        f"Possible man-in-the-middle attack."
                    ),
                    src_ip=ip,
                    src_mac=mac
                )
            else:
                print(f"[ARP DETECTOR] ARP spoofing already alerted for {ip} (skipping duplicate)")
        else:
            # Same MAC, no spoofing
            pass
    else:
        # First time seeing this IP, store it
        print(f"[ARP DETECTOR] First time seeing {ip} -> {mac}, adding to ARP table")
        arp_table[ip] = mac

    # Update ARP table with current MAC (always update to latest)
    arp_table[ip] = mac

    # ==================================================
    # 2️⃣ ARP FLOODING DETECTION
    # ==================================================
    arp_rate[ip].append(now)

    # Use configurable thresholds (can be updated from admin panel)
    WINDOW = ARP_FLOOD_TIME_WINDOW
    THRESHOLD = ARP_FLOOD_THRESHOLD

    # Keep only timestamps in sliding window
    arp_rate[ip] = [t for t in arp_rate[ip] if now - t <= WINDOW]

    if len(arp_rate[ip]) > THRESHOLD and ip not in alerted_flood:
        print(f"[ARP DETECTOR] ARP Flood detected: {len(arp_rate[ip])} packets from {ip} in {WINDOW}s (threshold: {THRESHOLD})")
        alerted_flood.add(ip)
        return SecurityEvent(
            category="ARP Flooding",
            severity="MEDIUM",
            message=(
                f"ARP flooding detected from {ip} | "
                f"{len(arp_rate[ip])} ARP packets in {WINDOW}s"
            ),
            src_ip=ip,
            src_mac=mac
        )
    elif len(arp_rate[ip]) > THRESHOLD * 0.8:  # Log when approaching threshold
        print(f"[ARP DETECTOR] Approaching ARP flood threshold: {len(arp_rate[ip])}/{THRESHOLD} packets from {ip}")

    # No attack
    return None
