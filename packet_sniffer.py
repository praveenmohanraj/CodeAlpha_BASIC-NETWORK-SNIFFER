import os
from scapy.all import *

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        print(f"IP Packet: {src_ip} -> {dst_ip}, Protocol: {protocol}")

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        if UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"UDP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        if ICMP in packet:
            print(f"ICMP Packet: {src_ip} -> {dst_ip}")

def sniff_packets(interface, filter=None):
    print("Starting packet sniffing...")
    try:
        sniff(iface=interface, filter=filter, prn=packet_callback, store=0, opened_socket=conf.L3socket6())
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    os.system("clear" if os.name == "posix" else "cls")
    print("Advanced Network Sniffer")
    interface = input("Enter the Wi-Fi interface name (e.g., wlan0): ")
    filter_str = input("Enter filter expression (leave empty for all traffic): ")
    sniff_packets(interface, filter_str)