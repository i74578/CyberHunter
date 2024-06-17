from logging_config import setup_logger
from mac_vendor_lookup import MacLookup, BaseMacLookup
from scapy.all import Dot11, sniff, RadioTap, Dot11Beacon, Dot11Elt, EAPOL
import threading
import os

logger = setup_logger(__name__)

class Sniffer:
    
    BaseMacLookup.cache_path = "./vendorMacCache"

    def __init__(self,db_interface,interfaces,network_update_callback):
        self.db_interface = db_interface
        self.network_update_callback = network_update_callback
        self.interfaces = interfaces
        self.stop_event = threading.Event()
        self.thread = []
        self.known_aps = []
        self.known_clients = []
        self.macLookup = MacLookup()
        if not os.path.isfile(BaseMacLookup.cache_path):
            self.macLookup.update_vendors()



    def start(self):
        self.stop_event.clear()
        th = threading.Thread(target=self._sniffer_thread)
        th.daemon = True
        th.name = "SnifferThread"
        self.thread.append(th)
        th.start()
        logger.debug("Sniffer: started")


    def _sniffer_thread(self):
        sniff(iface=self.interfaces, prn = self._PacketHandler,store=0,quiet=True,stop_filter=lambda x: self.stop_event.is_set())

    def stop(self):
        self.stop_event.set()
        for thread in self.thread:
            thread.join()
        self.thread = []
        
        logger.debug("Sniffer: stopped")

    def _PacketHandler(self,packet):
        if packet.haslayer(Dot11):
            # RTS, Block ack
            # Beacon frame
            if packet.type == 0 and packet.subtype == 8 and packet.haslayer(Dot11Beacon):
                beaconInfo = packet[Dot11Beacon].network_stats()
                if not "channel" in beaconInfo:
                    beaconInfo['channel'] = self._freq_to_channel(packet[RadioTap].Channel)
                beacon_ap_mac = packet.addr3.replace(":","")
                if not beacon_ap_mac in self.known_aps:
                    AP_vendor = self._MAC_lookup(beacon_ap_mac)
                    logger.info('Discovered new AP: ' + str(beacon_ap_mac) + " : " + str(beaconInfo['ssid']) + " : " + str(AP_vendor)+ " : " +str(beaconInfo['channel']))
                    pmfState = self._getPMFstatus(packet)
                    rowId = self.db_interface.add_ap(beacon_ap_mac,beaconInfo['ssid'],AP_vendor,beaconInfo['channel'],', '.join(beaconInfo['crypto']),pmfState)
                    self.network_update_callback({'table':'APs',"rowId":rowId})
                    self.known_aps.append(beacon_ap_mac)

            # Data frame
            # Assume that non-EAPOL data frames, indicate stations are associated 
            if packet.type == 2 and not packet.haslayer(EAPOL):
                to_ds = packet.FCfield & 0x1 != 0
                from_ds = packet.FCfield & 0x2 != 0
                if not to_ds == from_ds:
                    BSSID = ""
                    Client = ""
                    if not to_ds and from_ds:
                        BSSID = packet.addr2 .replace(":","")
                        Client = packet.addr1.replace(":","")
                    elif to_ds and not from_ds:
                        BSSID = packet.addr1.replace(":","")
                        Client = packet.addr2.replace(":","")
                    if not Client in self.known_clients and self._isUnicast(Client):
                        vendor = self._MAC_lookup(Client)
                        logger.info('Discovered new Client: ' + str(Client) + " AP:" + str(BSSID) + " : " + str(vendor))
                        rowId = self.db_interface.add_client(Client,BSSID,vendor)
                        self.network_update_callback({'table':'Clients',"rowId":rowId})
                        self.known_clients.append(Client)

            # Block ACK and RTS
            # Assume that block ACK and RTS frames, indicate stations are associated 
            if packet.type == 1 and (packet.subtype == 9 or packet.subtype == 11):
                
                addr1 = packet.addr1.replace(":","")
                addr2 = packet.addr2.replace(":","")

                if addr1 in self.known_aps and addr2 not in self.known_clients:
                    vendor = self._MAC_lookup(addr2)
                    logger.info('Discovered new Client: ' + str(addr2) + " AP:" + str(addr1) + " : " + str(vendor))
                    rowId = self.db_interface.add_client(addr2,addr1,vendor)
                    self.network_update_callback({'table':'Clients',"rowId":rowId})
                    self.known_clients.append(addr2)

                if addr2 in self.known_aps and addr1 not in self.known_clients:
                    vendor = self._MAC_lookup(addr1)
                    logger.info('Discovered new Client: ' + str(addr1) + " AP:" + str(addr2) + " : " + str(vendor))
                    rowId = self.db_interface.add_client(addr1,addr2,vendor)
                    self.network_update_callback({'table':'Clients',"rowId":rowId})
                    self.known_clients.append(addr1)


                #print("Subtype:"+str(packet.subtype)+" Addr1:"+str(packet.addr1)+" Addr2:"+str(packet.addr2))





    # least-significant bit of the most significant byte of the address
    # 0: unicast
    # 1: multicast
    #Src: https://www.ietf.org/archive/id/draft-ietf-madinas-mac-address-randomization-08.html
    def _isUnicast(self,addr):
        MSB = int(addr[0:2], 16)
        if not MSB & 1:
            logger.info(str(addr) + " is unicast ")
        else:
            logger.info(str(addr) + " is NOT unicast ")
        return not MSB & 1


    # second-least-significant bit of the most significant byte of the address
    # 0: globally unique (OUI enforced)
    # 1: locally administered
    #Src: https://www.ietf.org/archive/id/draft-ietf-madinas-mac-address-randomization-08.html
    def _isLocallyAdministered(self,addr):
        MSB = int(addr[0:2], 16)
        return (MSB >> 1) & 1

    def _MAC_lookup(self,addr):
        if self._isLocallyAdministered(addr):
            return "Random"
        try:
            return self.macLookup.lookup(addr)
        except:
            return "Unknown"

    def _getPMFstatus(self,beacon):
        dot11elt = beacon.getlayer(Dot11Elt)
        # Itterate through layers to get RNS IE layer
        while dot11elt and dot11elt.ID != 48:
                dot11elt = dot11elt.payload.getlayer(Dot11Elt)
        # If RNS information IE is found, continue
        if dot11elt != None and dot11elt.ID == 48:
            rsne = dot11elt.info
            # Start after RSN version field
            cur = 2
            # If next field is Group Data Cipher Suite, skip it
            cipher = int.from_bytes(rsne[cur:cur+3], byteorder='big')
            if cipher == 0x000fac:
                cur += 4
            # Skip though Pairwise Cipher Suite and AKM Suite
            for i in range(2):
                # Check if next field is a counter, by checking next bytes OUI
                cipher = int.from_bytes(rsne[cur+2:cur+5], byteorder='big')
                if cipher == 0x000fac:
                    suiteCounter = int.from_bytes(rsne[cur:cur+2], byteorder='little')
                    # Skip Count field
                    cur += 2
                    # Skip Suite List
                    cur += 4*suiteCounter
            RNScapabilities = int.from_bytes(rsne[cur:cur+2], byteorder='little')
            # Extract management frame protection required tag
            MFPR = RNScapabilities >> 6 & 1
            # Extract management frame protection capable tag
            MFPC = RNScapabilities >> 7 & 1
            if MFPR:
                return 2
            elif MFPC:
                return 1
            else:
                return 0
        else:
            beaconInfo = beacon[Dot11Beacon].network_stats()
            security = ', '.join(beaconInfo['crypto'])
            if security == "OPN":
                return 0
        return -1
    
    def _freq_to_channel(self,freq):
            lookup_table = {2412:1,2417:2,2422:3,2427:4,2432:5,2437:6,2442:7,2447:8,2452:9,2457:10,2462:11,2467:12,2472:13,2484:14,5075:15,5080:16,5085:17,5090:18,5100:20,5120:24,5140:28,5160:32,5180:36,5200:40,5220:44,5240:48,5260:52,5280:56,5300:60,5320:64,5340:68,5360:72,5380:76,5400:80,5420:84,5440:88,5460:92,5480:96,5500:100,5520:104,5540:108,5560:112,5580:116,5600:120,5620:124,5640:128,5660:132,5680:136,5700:140,5720:144,5745:149,5765:153,5785:157,5805:161,5825:165,5845:169,5865:173,5885:177}
            return lookup_table[freq]
