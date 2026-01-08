try:
    from scapy.all import get_if_list, sniff
    print("Scapy imported successfully.")
    
    interfaces = get_if_list()
    print(f"Interfaces found: {interfaces}")
    
    if not interfaces:
        print("ERROR: No interfaces found. Npcap might be missing or not working.")
    else:
        print("Attempting to sniff 1 packet...")
        try:
            sniff(count=1, timeout=3)
            print("Sniffing successful.")
        except Exception as e:
            print(f"Sniffing failed: {e}")

except Exception as e:
    print(f"Scapy import or execution failed: {e}")
