#!/usr/bin/env python
from scapy.all import *
import socket
import sys

def knock(set_ports):
    filter_string = "tcp port "
    current_port = set_ports

    print current_port

    while True:
	packet = sniff(filter=filter_string+str(current_port[0]), count=1)
	packsrc = packet[0].getlayer(IP).src
	
	for port in current_port:
	    if port == current_port[0]:
		continue

	    print "New port: ", port

	    packet = sniff(filter=filter_string+str(port), count=1, timeout=5)
	    #print port
	    if len(packet) < 1:
		print "No cigar"
		break

	    if port == packet[0].getlayer(IP).dport:
		continue
	    
        if len(packet) < 1:
		    print "less than"
		    continue

if len(sys.argv) < 3:
    print "Server Mode Usage: ./knock -s ports(comma separated)"
    exit()
if sys.argv[1] != '-s':
    print "Not a valid option"
    exit()

ports = sys.argv[2].split(',')

if len(ports) < 2:
    print "Not enough ports, please define at least two"

knock(ports)
