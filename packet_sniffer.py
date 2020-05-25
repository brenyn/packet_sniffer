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

def sniff(interface):
	scapy.sniff(iface = interface, store = False, prn = process_sniffed_packet)

def process_sniffed_packet(packet):
	print(packet)

sniff("eth0")