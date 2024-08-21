#!/usr/bin/python3

import scapy.all as scp
import argparse as agp


def parse_Method():
	parser = agp.ArgumentParser(
				prog="neteye.py",
				description="Simple net discovery app to reveal the IP & MAC addresses of the devices in a specific network range.",
				epilog="python3 neteye.py -r [IP Range]")
	parser.add_argument("-r", "--range", dest="ip_range", required=True, help="Specify the IP range (eg. 192.168.1.0/24")
	args = parser.parse_args()
	return args

def ARP_Action(ip):
	arp_req = scp.ARP(pdst=ip)
	broadcast_packet = scp.Ether(dst="ff:ff:ff:ff:ff:ff")
	combined_packet = broadcast_packet/arp_req
	return combined_packet

def ARP_Response(combined_packet):
	(answered_list,unanswered_list) = scp.srp(combined_packet,timeout=1)
	answered_list.summary()

args = parse_Method()

output = ARP_Action(args.ip_range)
ARP_Response(output)
