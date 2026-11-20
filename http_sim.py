#!/usr/bin/env python3
"""Simulate an HTTP GET request using Scapy to a target server with a custom Host header."""

import platform
import sys

from scapy.all import IP, TCP, Raw, sr1, send, RandShort

print("=" * 60)
print("  Scapy HTTP Request Simulator")
print("=" * 60)
print()
print("NOTE: Your OS kernel may send its own RST when the SYN-ACK")
print("arrives (it doesn't know about Scapy's connection). If the")
print("handshake fails, suppress the kernel RST first:")
print()
if platform.system() == "Darwin":
    print("  macOS:")
    print('    sudo pfctl -e')
    print('    echo "block drop out proto tcp from any to <DST_IP> flags R/R" \\')
    print('      | sudo pfctl -f -')
else:
    print("  Linux (iptables):")
    print("    sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST \\")
    print("      -d <DST_IP> -j DROP")
print()
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
print()

sport = int(RandShort())

# SYN
syn = IP(dst=DST_IP) / TCP(sport=sport, dport=DST_PORT, flags="S", seq=1000)
print(f"[*] Sending SYN to {DST_IP}:{DST_PORT} (sport={sport})")
syn_ack = sr1(syn, timeout=5, verbose=0)

if syn_ack is None or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 0x12:
    print("[!] No SYN-ACK received. Server may be unreachable.")
    raise SystemExit(1)

print(f"[*] Received SYN-ACK (seq={syn_ack[TCP].seq}, ack={syn_ack[TCP].ack})")

# ACK to complete handshake
ack = IP(dst=DST_IP) / TCP(
    sport=sport, dport=DST_PORT, flags="A",
    seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1,
)
send(ack, verbose=0)
print("[*] Sent ACK — handshake complete")

# HTTP GET
http_payload = (
    f"GET / HTTP/1.1\r\n"
    f"Host: {HOST_HEADER}\r\n"
    f"User-Agent: scapy-http-sim/1.0\r\n"
    f"Accept: */*\r\n"
    f"Connection: close\r\n"
    f"\r\n"
)

http_req = IP(dst=DST_IP) / TCP(
    sport=sport, dport=DST_PORT, flags="PA",
    seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1,
) / Raw(load=http_payload)

print(f"[*] Sending HTTP GET with Host: {HOST_HEADER}")
response = sr1(http_req, timeout=5, verbose=0)

if response and response.haslayer(Raw):
    print(f"[*] Response received ({len(response[Raw].load)} bytes):")
    print(response[Raw].load.decode(errors="replace")[:500])
elif response:
    print(f"[*] Response received (no payload, flags={response[TCP].flags:#x})")
else:
    print("[!] No response received")

# RST to tear down
rst = IP(dst=DST_IP) / TCP(
    sport=sport, dport=DST_PORT, flags="RA",
    seq=http_req[TCP].seq + len(http_payload),
    ack=response[TCP].seq + 1 if response and response.haslayer(TCP) else 0,
)
send(rst, verbose=0)
print("[*] Sent RST — connection closed")
