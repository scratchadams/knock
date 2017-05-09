#!/usr/bin/env python
from scapy.all import *
import socket
import sys
import time

def execFunc(string):
    print string

def func(new_func, args):
    new_func(args)

def knock_back(set_ports, ipaddr):
    for port in set_ports:
	print "ip: " + ipaddr + " port: " + port
	packet = IP(dst=ipaddr)/TCP(dport=int(port))
    
	send(packet)
	time.sleep(2)

def knock(set_ports):
    filter_string = "tcp port "
    current_port = set_ports

    print current_port

    while True:
	packet = sniff(filter=filter_string+str(current_port[0]), count=1)
	packsrc = packet[0].getlayer(IP).src
	
	for port in current_port:
	    if port == current_port[0]:
		print "Port Match"
		continue

	    packet = sniff(filter=filter_string+str(port), count=1, timeout=5)
	    #print port
	    if len(packet) < 1:
		print "No cigar"
		break

	    if port == str(packet[0].getlayer(IP).dport):
		if port == current_port[len(current_port)-1]:
		    print "Success"
		    func(execFunc, ("test"))
		    continue

		print "Port Match"
		continue
	    
if len(sys.argv) < 3:
    print "Server Mode Usage: ./knock -s ports(comma separated)"
    exit()

if sys.argv[1] == '-s':
    ports = sys.argv[2].split(',')
    if len(ports) < 2:
	print "Not enough ports, please define at least two"
	exit()
    knock(ports)

elif sys.argv[1] == '-c':
    ports = sys.argv[2].split(',')
    if len(ports) < 2:
	print "Not enough ports, please define at least two"
	exit()

    knock_back(ports, "127.0.0.1")

