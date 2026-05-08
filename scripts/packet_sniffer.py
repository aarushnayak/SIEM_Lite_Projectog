# packet_sniffer.py (Live Network Traffic Monitor)
import os
from datetime import datetime
from scapy.all import sniff, IP, TCP 
import logging

# --- Interface Configuration (REMOVED - Ab Scapy khud interface dhundhega) ---
# INTERFACE = "Wi-Fi" # <--- Yeh line hata di gayi hai!
INTERFACE = "AUTO" # Bas console message ke liye

# --- Constants aur Paths ---
BASE_DIR = os.path.dirname(__file__)
LOG_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "logs", "auth_dummy.log"))

# File logging ko set karte hain
logging.basicConfig(level=logging.INFO, format='%(message)s')

# --- Helper Function ---
def write_line(line):
    with open(LOG_PATH, "a", encoding='utf-8') as f:
        f.write(line + "\n")
    print("WROTE:", line)

# --- Packet Processing Logic ---
def process_packet(packet):
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst

        if packet.haslayer(TCP):
            dest_port = packet[TCP].dport
            
            ts = datetime.now().strftime('%b %d %H:%M:%S')
            main_ip = dest_ip
            
            # Private IPs ko ignore karo
            if main_ip.startswith('192.168.') or main_ip.startswith('10.') or main_ip == '127.0.0.1':
                return

            # Line ko format karo (Ab INTERFACE ko AUTO dikhayenge)
            formatted_line = f"{ts} packet_sniffer: IN=AUTO SRC={main_ip} DST={source_ip} DST_PORT={dest_port}"
            
            write_line(formatted_line)

# --- Main Sniffing Logic ---
def main():
    print("Starting Packet Sniffer...")
    print(f"Interface mode: {INTERFACE} (Scapy will attempt to find a valid one)")
    print("Capturing live network traffic. Press Ctrl+C to stop.")
    
    try:
        # iface parameter ko hata diya gaya hai!
        sniff(prn=process_packet, filter="tcp", store=0, timeout=120) 
    except Exception as e:
        print(f"\n[CRITICAL ERROR] Failed to sniff.")
        print("Possible reasons: 1. Npcap not installed/configured correctly. 2. No active TCP connection found.")
        print(f"Scapy Error: {e}")

if __name__ == "__main__":
    try:
        print("IMPORTANT: This script MUST be run with Administrator privileges.")
        main()
    except PermissionError:
        print("\n[ERROR] Permission denied. Please run this script as an Administrator.")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")