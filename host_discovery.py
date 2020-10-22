"""
Python Version 3.8

Singapore Institute of Technology (SIT)
Information and Communications Technology (Information Security), BEng (Hons)

ICT-2203 Network Security Assignment 1

Author: @ Tan Zhao Yea / 1802992
Academic Year: 2020/2021
Lecturer: Dr. Woo Wing Keong
Submission Date: 25th October 2020

This script holds the code to perform Host Discovering in given CIDR Address.
"""

import sys
import random
from ipaddress import IPv4Network
from scapy.all import *

# Default Configurations
ALIVE_HOST = []
PORTS = range(1,51)

# TCP Flags
SYN = 0x02
SYN_ACK = 0x12
ACK = 0x10
RST = 0x04
CLOSE_PORT = 0x14


# Layer 4 Address
MY_IP = get_if_addr(conf.iface)


def icmp_scan(host):
	""" 
	Scanning for Alive Host 
	:param host: Target IP Address of host
	"""

	ans = sr1(IP(dst=host)/ICMP(), timeout=1, verbose=0)
	if not ans is None:
		ALIVE_HOST.append(host)


def tcp_syn_scan(host, dport):
	""" 
	TCP SYN Scan to scan for open ports 
	:param host: Target IP Address of host
	"""
	sport = random.randint(1025,65534)
	ans = sr1(IP(dst=host)/TCP(sport=sport,dport=dport, flags=SYN), timeout=1, verbose=0)
	
	if ans.haslayer(TCP):
		if ans[TCP].flags == SYN_ACK:
			# Send a RST to close the connection
			rst_pkt = IP(dst=host)/TCP(sport=sport,dport=dport,flags=RST)
			send(rst_pkt, verbose=0)

			print(f"\t[+] {host}:{dport} is open.")

		# Showing Close Ports
		# elif (ans.getlayer(TCP).flags == CLOSE_PORT):
			# print(f"{host}:{dport} is closed.")


def main(host_addr):
	""" 
	Main Function running icmp scan as well as service scan

	:param host_addr: String containing CIDR of Host, E.g. 192.168.0.1/24
	"""
	try:
		# Perform Ping Scan
		print("[*] Starting Ping Scan to find Alive Hosts")
		print(f"\t[+] My IP Address is: {MY_IP}, Skipping scan ...")
		for ip in list(IPv4Network(host_addr))[1:]:
			# Restrict ping scan to my own ip address
			if ip != MY_IP:
				icmp_scan(str(ip))
		
		# Perform TCP SYN Scan
		for alive_ip in ALIVE_HOST:
			print(f"[*] {alive_ip} is alive, scanning for open ports ...")
			
			for dport in PORTS:
				tcp_syn_scan(alive_ip, dport)


	except ValueError:
		print(f"[ERR] {host_addr} has host bits set")


if __name__ == '__main__':
	args = sys.argv[1:]

	if len(args) != 1:
		print("[*] Usage: python3 host_discovery.py <Network Address/Net Mask>")
		print("[*] Example: python3 host_discovery.py 192.168.1.0/24")

	else:
		host_addr = args[0]
		main(host_addr)