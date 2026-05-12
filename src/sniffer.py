from scapy.all import sniff, IP, TCP, UDP, Raw
import datetime

# Define colors for terminal output
RED = "\033[91m"
RESET = "\033[0m"

def analyze_packet(packet):
    """Analyzes captured packets for potential security risks."""
    if packet.haslayer(IP):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        # Determine protocol name
        protocol_name = "OTHER"
        if packet.haslayer(TCP): protocol_name = "TCP"
        elif packet.haslayer(UDP): protocol_name = "UDP"

        # 1. Flag Unencrypted Traffic (Security Risk)
        alert_msg = ""
        if packet.haslayer(TCP):
            # Port 21 (FTP), 23 (Telnet), 80 (HTTP)
            if packet[TCP].dport in [21, 23, 80]:
                alert_msg = f"{RED}[ALERT: UNENCRYPTED PROTOCOL]{RESET}"

        # 2. Check for suspicious Payload (Basic Signature Matching)
        if packet.haslayer(Raw):
            payload = str(packet[Raw].load)
            if "admin" in payload.lower() or "password" in payload.lower():
                alert_msg = f"{RED}[ALERT: SENSITIVE KEYWORD DETECTED]{RESET}"

        # Print the results
        output = f"[{timestamp}] {src_ip} -> {dst_ip} | {protocol_name} {alert_msg}"
        print(output)

def main():
    print("--- Lumina-Sniff: Network Security Monitor ---")
    print("Listening for traffic... (Press Ctrl+C to stop)")
    
    # Start sniffing. 'store=0' keeps memory usage low.
    try:
        sniff(prn=analyze_packet, store=0)
    except PermissionError:
        print("Error: You must run this script as root/admin.")

if __name__ == "__main__":
    main()
