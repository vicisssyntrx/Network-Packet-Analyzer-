from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] Packet:")
        print(f"    Source IP: {ip_layer.src}")
        print(f"    Destination IP: {ip_layer.dst}")
        
        if TCP in packet:
            print("    Protocol: TCP")
        elif UDP in packet:
            print("    Protocol: UDP")
        elif ICMP in packet:
            print("    Protocol: ICMP")
        else:
            print("    Protocol: Other")

        if packet.haslayer(Raw):
            print(f"    Payload: {packet[Raw].load}")

print("Starting packet sniffer... Press CTRL+C to stop.\n")
sniff(prn=process_packet, store=False)
