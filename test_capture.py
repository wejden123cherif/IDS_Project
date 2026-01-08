"""
Quick test script to verify Scapy packet capture is working
Run this to diagnose packet capture issues
"""
import sys
import platform

print("=" * 60)
print("Scapy Packet Capture Test")
print("=" * 60)

# Check Python version
print(f"Python version: {sys.version}")

# Check platform
print(f"Platform: {platform.system()} {platform.release()}")

# Try to import Scapy
try:
    from scapy.all import sniff, get_if_list, conf
    print("[OK] Scapy imported successfully")
except ImportError as e:
    print(f"[ERROR] Failed to import Scapy: {e}")
    print("    Install with: pip install scapy")
    sys.exit(1)

# Check interfaces
try:
    interfaces = get_if_list()
    print(f"[OK] Found {len(interfaces)} network interfaces:")
    for i, iface in enumerate(interfaces, 1):
        print(f"    {i}. {iface}")
except Exception as e:
    print(f"[ERROR] Failed to list interfaces: {e}")
    sys.exit(1)

# Check if we can sniff
print("\n[*] Attempting to capture packets for 5 seconds...")
print("[*] Try browsing the web or generating network traffic...")

packet_count = [0]

def test_callback(packet):
    packet_count[0] += 1
    if packet_count[0] <= 5:  # Print first 5 packets
        print(f"  Packet {packet_count[0]}: {packet.summary()}")

try:
    if platform.system() == 'Windows':
        print("[*] On Windows, using default interface (may require Npcap)")
        print("[*] If this fails, install Npcap from: https://npcap.com/")
        sniff(timeout=5, prn=test_callback, store=False)
    else:
        if interfaces:
            print(f"[*] Using interface: {interfaces[0]}")
            sniff(iface=interfaces[0], timeout=5, prn=test_callback, store=False)
        else:
            print("[!] No interfaces found")
            sys.exit(1)
    
    print(f"\n[OK] Capture test complete!")
    print(f"[*] Total packets captured: {packet_count[0]}")
    
    if packet_count[0] == 0:
        print("\n[!] WARNING: No packets captured!")
        print("    Possible issues:")
        print("    1. No network activity (try browsing the web)")
        print("    2. Need Administrator/root privileges")
        print("    3. On Windows: Install Npcap (https://npcap.com/)")
        print("    4. Firewall blocking packet capture")
    else:
        print("[OK] Packet capture is working correctly!")
        
except PermissionError:
    print("\n[ERROR] Permission denied!")
    print("    Run this script as Administrator (Windows) or with sudo (Linux/Mac)")
except Exception as e:
    print(f"\n[ERROR] Error during capture: {e}")
    import traceback
    traceback.print_exc()
    if platform.system() == 'Windows':
        print("\n[!] On Windows, you may need to install Npcap:")
        print("    Download from: https://npcap.com/")
        print("    Make sure to install with 'WinPcap API-compatible Mode' enabled")

print("\n" + "=" * 60)
