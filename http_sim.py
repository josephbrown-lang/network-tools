#!/usr/bin/env python3
"""Send a crafted HTTP GET packet using Scapy with a custom Host header.

Sends a single PSH-ACK packet with an HTTP GET payload — no TCP handshake.
Useful for testing DPI and application classification engines.
"""

import sys

from scapy.all import IP, TCP, Raw, send, RandShort

print("=" * 60)
print("  Scapy HTTP Request Simulator")
print("=" * 60)
print()

DST_IP = input("Enter destination IP address: ").strip()
if not DST_IP:
    print("[!] No IP address provided.")
    sys.exit(1)

HOST_HEADER = input("Enter domain name for Host header: ").strip()
if not HOST_HEADER:
    print("[!] No Host header provided.")
    sys.exit(1)

DST_PORT = 80
sport = int(RandShort())

http_payload = (
    f"GET / HTTP/1.1\r\n"
    f"Host: {HOST_HEADER}\r\n"
    f"\r\n"
)

pkt = (
    IP(dst=DST_IP)
    / TCP(sport=sport, dport=DST_PORT, flags="PA", seq=1, ack=1)
    / Raw(load=http_payload)
)

print()
print(f"[*] Sending HTTP GET to {DST_IP}:{DST_PORT} (sport={sport})")
print(f"[*] Host: {HOST_HEADER}")
send(pkt, verbose=0)
print("[*] Packet sent")
