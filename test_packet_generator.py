"""
Test Packet Generator
Sends test ARP and SYN packets to verify the detection system is working.
Run this while monitoring is active to see packets appear in the dashboard.

WARNING: This sends real network packets. Use only on your own network for testing.
"""
import time
from scapy.all import ARP, IP, TCP, send, get_if_addr, conf
import sys

def send_test_arp_packets(count=5, target_ip=None):
    """Send test ARP packets"""
    print(f"[*] Sending {count} test ARP packets...")
    
    if not target_ip:
        # Try to get gateway IP (common target for ARP)
        try:
            import socket
            # Get default gateway (simplified - may not work on all systems)
            target_ip = get_if_addr(conf.iface)
            # Use a common gateway IP pattern
            parts = target_ip.split('.')
            if len(parts) == 4:
                target_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
            else:
                target_ip = "192.168.1.1"
        except:
            target_ip = "192.168.1.1"
    
    print(f"[*] Target IP: {target_ip}")
    
    for i in range(count):
        # Create ARP request
        arp = ARP(op=1, pdst=target_ip)  # op=1 is ARP request
        send(arp, verbose=False)
        print(f"  [*] Sent ARP packet {i+1}/{count}")
        time.sleep(0.5)
    
    print("[OK] ARP packets sent!")

def send_test_syn_packets(count=25, target_ip="8.8.8.8", target_port=80):
    """Send test SYN packets (SYN flood simulation)"""
    print(f"[*] Sending {count} test SYN packets to {target_ip}:{target_port}...")
    print("[*] This will trigger SYN flood detection if threshold is low enough")
    
    for i in range(count):
        # Create SYN packet
        syn = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
        send(syn, verbose=False)
        if (i + 1) % 5 == 0:
            print(f"  [*] Sent {i+1}/{count} SYN packets...")
        time.sleep(0.1)  # Small delay to avoid overwhelming
    
    print("[OK] SYN packets sent!")

if __name__ == "__main__":
    print("=" * 60)
    print("Test Packet Generator")
    print("=" * 60)
    print("\nThis script sends test packets to verify detection is working.")
    print("Make sure monitoring is ACTIVE in the admin panel first!\n")
    
    if len(sys.argv) > 1:
        test_type = sys.argv[1].lower()
    else:
        print("Choose test type:")
        print("  1. ARP packets (for ARP detection)")
        print("  2. SYN packets (for SYN flood detection)")
        print("  3. Both")
        choice = input("\nEnter choice (1/2/3): ").strip()
        
        if choice == "1":
            test_type = "arp"
        elif choice == "2":
            test_type = "syn"
        else:
            test_type = "both"
    
    try:
        if test_type in ["arp", "both"]:
            send_test_arp_packets(count=10)
            time.sleep(1)
        
        if test_type in ["syn", "both"]:
            send_test_syn_packets(count=25)
        
        print("\n[OK] Test complete! Check your dashboard for packets and alerts.")
        print("[*] Note: It may take a few seconds for packets to appear.")
        
    except PermissionError:
        print("\n[ERROR] Permission denied!")
        print("    Run this script as Administrator (Windows) or with sudo (Linux/Mac)")
    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
        import traceback
        traceback.print_exc()
