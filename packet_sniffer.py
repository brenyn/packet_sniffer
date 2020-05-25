#!/usr/bin/env python

##########################################################################################################
#
# Author: Brenyn Kissoondath
# Course: Learn Python and Ethical Hacking From Scratch - StationX
# Instructor: Zaid Al Quraishi
# Purpose: Create a packet sniffer
# Input(s): 
# Output(s): 
#
# Notes to self:
#
##########################################################################################################

import scapy.all as scapy
from scapy.layers import http #allows us to use http filters

def sniff(interface):
	scapy.sniff(iface = interface, store = False, prn = process_sniffed_packet)

def process_sniffed_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		if packet.haslayer(scapy.Raw):
			print(packet[scapy.Raw].load) # only print from load inside of raw layer

sniff("eth0")