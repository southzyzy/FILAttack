"""
Python Version 3.8

Singapore Institute of Technology (SIT)
Information and Communications Technology (Information Security), BEng (Hons)

ICT-2203 Network Security Assignment 1

Author: @ Tan Zhao Yea / 1802992
Academic Year: 2020/2021
Lecturer: Woo Wing Keong
Submission Date: 25th October 2020

This script holds the code to perform Host Discovering in given CIDR Address.
"""

import sys
import random
from ipaddress import IPv4Network
from scapy.all import *

# Default Configurations
ALIVE_HOST = []

# Commonly Used Ports
PORTS = {
	"FTP" : [21,22],
	"SSH" : 22,
	"Telnet" : 23,
	"SMTP" : 24,
	"IPSec" : [50,51],
	"DNS" : 53,
	"DHCP" :[67,68],
	"TFTP" : 69,
	"HTTP" : [80,8080],
	"HTTPS" : 443,
	"POP3" : 110,
	"NNTP" : 119,
	"NTP" : 123,
	"NetBIOS" : [135,136,137,138,139],
	"IMAP4" : 143,
	"LDAP" : 389,
	"RDP" : 3389
}


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


def tcp_syn_scan(host, service_name, dport):
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

			print(f"\t[+] {host}:{dport} is open. ({service_name})")

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
		print(f"\t[+] My IP Address is: {MY_IP}, ignoring this IP")
		for ip in list(IPv4Network(host_addr))[1:]:
			# Restrict ping scan to my own ip address
			if ip != MY_IP:
				icmp_scan(str(ip))
		
		# Perform TCP SYN Scan
		for alive_ip in ALIVE_HOST:
			print(f"[*] {alive_ip} is alive, scanning for open ports ...")
			
			for service_name, port_no in PORTS.items():
				if isinstance(port_no, list):
					for p in port_no:
						tcp_syn_scan(alive_ip, service_name, p)	
				else:
					tcp_syn_scan(alive_ip, service_name, port_no)


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