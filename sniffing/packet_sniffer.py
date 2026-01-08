from scapy.all import sniff, ARP, IP, TCP, conf
from datetime import datetime
import threading
import queue
import time
import sys
import os

# Detection modules - handle both absolute and relative imports
try:
    from sniffing import arp_detector
    from sniffing.syn_detector import SynDetector
except ImportError:
    # If running as a script, try relative imports
    try:
        import arp_detector
        from syn_detector import SynDetector
    except ImportError:
        # If still failing, add parent directory to path
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from sniffing import arp_detector
        from sniffing.syn_detector import SynDetector

class PacketCapture:
    def __init__(self, test_mode=False):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()
        self.capture_thread = None
        self.test_mode = test_mode  # If True, capture more packet types for testing

    # Packet filter & collector
    def packet_callback(self, packet):
        try:
            # ARP packets - always capture
            if packet.haslayer(ARP):
                self.packet_queue.put(packet)
                # Only print first few for debugging
                if hasattr(self, '_arp_count'):
                    self._arp_count += 1
                else:
                    self._arp_count = 1
                if self._arp_count <= 3:
                    print(f"[DEBUG] Captured ARP packet: {packet.summary()}")
            # TCP packets
            elif packet.haslayer(IP) and packet.haslayer(TCP):
                tcp = packet[TCP]
                # In test mode, capture ALL TCP packets; otherwise only SYN-only
                if self.test_mode:
                    # Test mode: capture all TCP packets
                    self.packet_queue.put(packet)
                    if hasattr(self, '_tcp_count'):
                        self._tcp_count += 1
                    else:
                        self._tcp_count = 1
                    if self._tcp_count <= 3:
                        print(f"[DEBUG] Captured TCP packet from {packet[IP].src} (test mode)")
                elif tcp.flags & 0x02 and not (tcp.flags & 0x10):  # SYN only (normal mode)
                    self.packet_queue.put(packet)
                    # Only print first few for debugging
                    if hasattr(self, '_syn_count'):
                        self._syn_count += 1
                    else:
                        self._syn_count = 1
                    if self._syn_count <= 3:
                        print(f"[DEBUG] Captured SYN packet from {packet[IP].src}")
        except Exception as e:
            print(f"Error in packet_callback: {e}")
            import traceback
            traceback.print_exc()

    # Start sniffing on chosen interface
    def start_capture(self, interface=None):
        print(f"[*] Starting packet capture on interface: {interface}")
        
        def capture_thread():
            try:
                import platform
                from scapy.all import get_if_list, conf
                
                # Determine which interface to use
                if not interface or interface == "Auto":
                    # Use None to let Scapy auto-detect default interface (WiFi on most systems)
                    sniff_iface = None
                    print(f"[*] Auto-detecting interface (will use default/WiFi interface)")
                    # Show available interfaces for reference
                    try:
                        ifaces = get_if_list()
                        if ifaces:
                            print(f"[*] Available interfaces: {len(ifaces)} found")
                            # Show first few non-loopback interfaces
                            non_loopback = [iface for iface in ifaces if 'Loopback' not in str(iface) and 'lo' not in str(iface).lower()]
                            if non_loopback:
                                print(f"[*] Non-loopback interfaces: {non_loopback[:3]}...")
                    except Exception as e:
                        print(f"[!] Could not list interfaces: {e}")
                else:
                    sniff_iface = interface
                    print(f"[*] Using specified interface: {sniff_iface}")
                
                # When None, Scapy will use the default interface (usually WiFi)
                if sniff_iface is None:
                    print(f"[*] Scapy will use default interface (typically WiFi)")
                
                print(f"[*] Starting packet capture...")
                if self.test_mode:
                    print(f"[*] TEST MODE: Capturing ALL TCP packets (not just SYN-only)")
                else:
                    print(f"[*] NORMAL MODE: Only capturing ARP and SYN-only TCP packets")
                print(f"[*] Waiting for packets... (this may take a moment)")
                
                # Add a test packet counter
                packet_count = [0]  # Use list to allow modification in nested function
                
                def callback_with_count(packet):
                    packet_count[0] += 1
                    # Only log every 100 packets to reduce spam
                    if packet_count[0] % 100 == 0:
                        print(f"[*] Sniffing active: {packet_count[0]} packets seen (filtering for ARP/SYN)...")
                    self.packet_callback(packet)
                
                sniff(
                    iface=sniff_iface,
                    prn=callback_with_count,
                    store=False,
                    stop_filter=lambda _: self.stop_capture.is_set()
                )
            except Exception as e:
                print(f"[!] Sniffing error: {e}")
                print(f"[!] Make sure you have Npcap or WinPcap installed on Windows!")
                print(f"[!] Download from: https://npcap.com/")
                import traceback
                traceback.print_exc()

        self.capture_thread = threading.Thread(target=capture_thread, daemon=True)
        self.capture_thread.start()

    # Stop sniffing cleanly
    def stop(self):
        self.stop_capture.set()
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)

def start_sniffing(interface=None, arp_table=None, alert_callback=None):
    """
    (Restored) Starts packet capture and processes packets until interrupted.
    """
    syn_detector = SynDetector()
    sniffer = PacketCapture()
    sniffer.start_capture(interface=interface)

    try:
        while True:
            # Simplified blocking loop for legacy support
            packet = sniffer.packet_queue.get()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # ---- ARP ----
            if packet.haslayer(ARP):
                # If arp_table is passed, use it, else ignore or use local
                if arp_table is not None:
                     evt = arp_detector.process_arp(packet, arp_table)
                     if evt and alert_callback:
                         alert_callback(
                            category=evt.category,
                            severity=evt.severity,
                            message=evt.message
                         )
            
            # ---- TCP SYN ----
            elif packet.haslayer(IP) and packet.haslayer(TCP):
                evt = syn_detector.process_syn(packet)
                if evt and alert_callback:
                     alert_callback(
                        category=evt.category,
                        severity=evt.severity,
                        message=evt.message
                     )

    except KeyboardInterrupt:
        print("\n[*] Stopping packet capture...")
        sniffer.stop()

# Prevent direct execution - this is a module, not a script
if __name__ == "__main__":
    print("=" * 60)
    print("ERROR: This file is a module, not a standalone script!")
    print("=" * 60)
    print("\nTo run the application, use:")
    print("  python app.py")
    print("\nOr to test packet capture, use:")
    print("  python test_capture.py")
    print("\nThis file (packet_sniffer.py) is imported by app.py")
    print("and should not be run directly.")
    print("=" * 60)
    sys.exit(1)
