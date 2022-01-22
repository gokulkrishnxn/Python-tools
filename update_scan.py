import threading
import time
from netaddr import IPNetwork,IPAddress
import socket
import os
import struct
from ctypes import *

host = "192.168.0.187" # change this to target
subnet = "192.168.0.0/24"

def __new__(self, socket_buffer):
	return self.from_buffer_copy(socket_buffer)

def __init__(self, socket_buffer):
	pass


class IP(Structure):
	_fields_ = [
	("ihl",          c_ubyte, 4), 
	("version",      c_ubyte, 4), 
	("tos",          c_ubyte),
	("len",          c_ushort),
	("id",           c_ushort),
	("offset",       c_ubyte),
	("ttl",          c_ubyte),
	("protocol_num", c_ubyte),
	("sum",          c_ulong),
	("src",          c_ulong),
	("dst",          c_ulong)
]


def udp_sender(subnet):
	time.sleep(5)
	sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	for ip in IPNetwork(subnet):

		try:
			sender.sendto(magic_message,("%s", % ip,65212))
		except:
			pass

			# map protocol constants to their names
	self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

	# humam readable IP address
	self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
	self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))

	# human readable protocol
	try:
		self.protocol = self.protocol_map[self.protocol_num]
	except:
		self.protocol = str(self.protocol_num)


# create a raw socket and bind it to the public interface
if os.name == "nt":
	socket_protocol = socket.IPPROTO_IP
else:
	socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket_protocol)

sniffer.bind((host, 0))

# we want the IP header include in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# if we're using windows we need to send to an IOCTL
# to set up promiscuous mode
if os.name == "nt":
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


t = threading.Thread(target=udp_sender,args=(subnet))
t.start()

try:
	while True:
		raw_buffer = sniffer.recvfrom(65565)[0]

		# create an IP header from the first 20 bytes of the buffer
		ip_header = IP(raw_buffer[0:20])

		# if it's ICMP, we want it
		if ip_header.protocol == "ICMP":

			# calculate where our ICMP packet starts
			offset = ip_header.ihl * 4

			buffer = raw_input[offset:offset + sizeof(ICMP)]

			# create our ICMP structure
			icmp_header = ICMP(buf)

			print "ICMP --> Type: %d Code: %d" % (icmp_header.type,icmp_header.code)

except keyboardInterrupt:

# if we're using windows turn off promiscuous mode
if os.name == "nt":
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

		print "ICMP --> Type: %d Code: %d" % (icmp_header.type, icmp_header.code)

		if icmp_header.code == 3 and icmp_header.type == 3:
			if IPAddress(ip_header.src_address) in IPNetwork(subnet):
				print "Host Up: %s" % ip_header.src_address
