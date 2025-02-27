import pyshark
import scapy.all as scapy
import os
import json

from scapy.all import get_if_list

# Get the list of all available interfaces
interfaces = get_if_list()

# Print the interfaces
print(interfaces)

# Define a dictionary to store file transfers
file_transfers = {}

# Function to extract file names from SMB, FTP, or HTTP packets
def extract_file_name(packet):
    try:
        if 'SMB' in packet:
            return packet.smb.file_name
        elif 'FTP' in packet:
            return packet.ftp.request_arg
        elif 'HTTP' in packet:
            return packet.http.request_uri
    except AttributeError:
        return None
    return None

# Packet handler function
def packet_callback(packet):
    file_name = extract_file_name(packet)
    if file_name:
        file_path = os.path.abspath(file_name)
        if file_path not in file_transfers:
            file_transfers[file_path] = []
        file_transfers[file_path].append(str(packet))

# Start capturing packets
def start_sniffing(interface="\\Device\\NPF_{0E8DA30F-9958-413A-B3CF-BA223E40CB7C}", packet_count=100):
    print("Starting packet sniffing...")
    capture = pyshark.LiveCapture(interface=interface)
    for packet in capture.sniff_continuously(packet_count=packet_count):
        packet_callback(packet)
        
    print("Packet sniffing completed.")
    save_results()

# Save results to a JSON file
def save_results():
    with open("file_transfer_log.json", "w") as log_file:
        json.dump(file_transfers, log_file, indent=4)
    print("Logs saved to file_transfer_log.json")

# Run the script
if __name__ == "__main__":
    start_sniffing()
