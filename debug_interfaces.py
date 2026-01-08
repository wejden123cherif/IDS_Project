import socket
import scapy.all as scapy
from scapy.arch.windows import get_windows_if_list

def get_best_interface():
    """
    Try to find the interface used for internet connection.
    """
    try:
        # Connect to a public DNS server to find the local IP used for internet
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        print(f"[*] Local IP used for internet: {local_ip}")
        return local_ip
    except Exception as e:
        print(f"[!] Could not determine local IP: {e}")
        return None

def list_interfaces():
    print("="*60)
    print("INTERFACE DIAGNOSTICS")
    print("="*60)
    
    local_ip = get_best_interface()
    
    # Get detailed Windows interface list from Scapy
    if_list = get_windows_if_list()
    
    best_iface = None
    
    for i in if_list:
        name = i.get('name')
        description = i.get('description')
        ips = i.get('ips', [])
        guid = i.get('guid')
        
        print(f"\nName: {name}")
        print(f"Description: {description}")
        print(f"GUID: {guid}")
        print(f"IPs: {ips}")
        
        if local_ip and local_ip in ips:
            print(f"*** THIS APPEARS TO BE THE ACTIVE INTERFACE ***")
            best_iface = i
            
    print("\n" + "="*60)
    if best_iface:
        print(f"RECOMMENDATION: Use interface with GUID: {best_iface['guid']}")
        print(f"Scapy Name: {best_iface['name']}")
    else:
        print("Could not automatically determine the best interface.")
    print("="*60)

if __name__ == "__main__":
    list_interfaces()
