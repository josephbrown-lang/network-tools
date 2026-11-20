#!/usr/bin/env python3
"""Simulate an HTTP GET with a custom Host header using a full TCP handshake.

Performs SYN -> SYN-ACK -> ACK -> HTTP GET so the target edge creates a
tracked flow visible in VCO monitoring. Automatically suppresses the
kernel RST that would otherwise kill the connection before Scapy can
complete the handshake.
"""

import atexit
import platform
import subprocess
import sys

from scapy.all import IP, TCP, Raw, sr1, send, RandShort

SYSTEM = platform.system()


def add_rst_block(dst_ip):
    if SYSTEM == "Darwin":
        anchor = f"scapy_block_{dst_ip.replace('.', '_')}"
        rule = f'block drop out proto tcp from any to {dst_ip} flags R/R'
        subprocess.run(
            ["pfctl", "-a", anchor, "-f", "-"],
            input=rule.encode(), capture_output=True,
        )
        subprocess.run(["pfctl", "-e"], capture_output=True)
        return anchor
    else:
        subprocess.run([
            "iptables", "-A", "OUTPUT",
            "-p", "tcp", "--tcp-flags", "RST", "RST",
            "-d", dst_ip, "-j", "DROP",
        ], capture_output=True)
        return None


def remove_rst_block(dst_ip, anchor):
    if SYSTEM == "Darwin" and anchor:
        subprocess.run(["pfctl", "-a", anchor, "-F", "rules"], capture_output=True)
    else:
        subprocess.run([
            "iptables", "-D", "OUTPUT",
            "-p", "tcp", "--tcp-flags", "RST", "RST",
            "-d", dst_ip, "-j", "DROP",
        ], capture_output=True)


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
print()

# Block kernel RST so Scapy can complete the handshake
print("[*] Suppressing kernel RST packets...")
anchor = add_rst_block(DST_IP)
atexit.register(remove_rst_block, DST_IP, anchor)

# SYN
syn = IP(dst=DST_IP) / TCP(sport=sport, dport=DST_PORT, flags="S", seq=1000)
print(f"[*] Sending SYN to {DST_IP}:{DST_PORT} (sport={sport})")
syn_ack = sr1(syn, timeout=5, verbose=0)

if syn_ack is None or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 0x12:
    print("[!] No SYN-ACK received. Server may be unreachable.")
    sys.exit(1)

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
    print(f"[*] Response received (flags={str(response[TCP].flags)})")
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

# Cleanup happens via atexit
print("[*] Kernel RST rule removed")
