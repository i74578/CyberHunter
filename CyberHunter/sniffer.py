import threading
import os

from logging_config import setup_logger
from mac_vendor_lookup import MacLookup, BaseMacLookup, VendorNotFoundError
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.layers.eap import EAPOL
from scapy.all import sniff

logger = setup_logger(__name__)


class Sniffer:
    BaseMacLookup.cache_path = "./vendorMacCache"

    def __init__(self, db_interface, interfaces, network_update_callback):
        self.db_interface = db_interface
        self.network_update_callback = network_update_callback
        self.interfaces = interfaces
        self.stop_event = threading.Event()
        self.thread = []
        self.known_aps = set()
        self.known_clients = set()
        self.mac_lookup = MacLookup()
        if not os.path.isfile(BaseMacLookup.cache_path):
            self.mac_lookup.update_vendors()

    def start(self):
        """ Start a sniffer on a new thread """
        self.stop_event.clear()
        th = threading.Thread(target=self._sniffer_thread)
        th.daemon = True
        th.name = "SnifferThread"
        self.thread.append(th)
        th.start()
        logger.debug("Sniffer: started")

    def _sniffer_thread(self):
        sniff(iface=self.interfaces, prn=self._packet_handler, store=0, quiet=True,
              stop_filter=lambda x: self.stop_event.is_set())

    def stop(self):
        """ Kill all running sniffer threads, and wait for them to die """
        self.stop_event.set()
        for thread in self.thread:
            thread.join()
        self.thread = []
        logger.debug("Sniffer: stopped")

    def _packet_handler(self, packet):
        if packet.haslayer(Dot11):
            # Process beacon frame
            if packet.type == 0 and packet.subtype == 8 and packet.haslayer(Dot11Beacon):
                beacon_info = packet[Dot11Beacon].network_stats()
                # Use radioTap channel if channel not specified in DS parameter set
                if "channel" not in beacon_info:
                    beacon_info['channel'] = self._freq_to_channel(packet[RadioTap].Channel)
                beacon_ap_bssid = packet.addr3.replace(":", "")
                if beacon_ap_bssid not in self.known_aps:
                    ap_vendor = self._get_mac_vendor(beacon_ap_bssid)
                    logger.info("Discovered new AP(%s) by vendor %s broadcasting \"%s\" on channel %s",
                                str(beacon_ap_bssid), str(ap_vendor), str(beacon_info['ssid']),
                                str(beacon_info['channel']))
                    pmf_config = self._parse_pmf_config(packet)
                    # Add AP to database, and note rowId
                    row_id = self.db_interface.add_ap(beacon_ap_bssid, beacon_info['ssid'], ap_vendor,
                                                      beacon_info['channel'], ', '.join(beacon_info['crypto']),
                                                      pmf_config)
                    # Add AP to cache lookup variable
                    self.known_aps.add(beacon_ap_bssid)
                    # Call callback funcion on the controller
                    self.network_update_callback({'table': 'APs', "rowId": row_id})

            # Process data non-EAPOL data frames
            # Assume that non-EAPOL data frames, indicate stations are associated
            if packet.type == 2 and not packet.haslayer(EAPOL):
                # Determine BSSID and SA/TA addresses by checking the following fields:
                # To_DS, From_DS, Addr1 and Addr2
                to_ds = packet.FCfield & 0x1 != 0
                from_ds = packet.FCfield & 0x2 != 0
                if not to_ds == from_ds:
                    bssid = ""
                    client = ""
                    if not to_ds and from_ds:
                        bssid = packet.addr2.replace(":", "")
                        client = packet.addr1.replace(":", "")
                    elif to_ds and not from_ds:
                        bssid = packet.addr1.replace(":", "")
                        client = packet.addr2.replace(":", "")
                    if client not in self.known_clients and self._is_unicast(client):
                        vendor = self._get_mac_vendor(client)
                        logger.info("Discovered new client(%s) by vendor %s connected to %s", str(client), str(vendor),
                                    str(bssid))
                        # Add client to database, and note rowId
                        row_id = self.db_interface.add_client(client, bssid, vendor)
                        # Add client to cache lookup variable
                        self.known_clients.add(client)
                        # Call callback funcion on the controller
                        self.network_update_callback({'table': 'Clients', "rowId": row_id})

            # Process block ACK and RTS frames
            # Assume that block ACK and RTS frames, indicate stations are associated
            if packet.type == 1 and (packet.subtype == 9 or packet.subtype == 11):
                addr1 = packet.addr1.replace(":", "")
                addr2 = packet.addr2.replace(":", "")

                if addr1 in self.known_aps and addr2 not in self.known_clients:
                    vendor = self._get_mac_vendor(addr2)
                    logger.info("Discovered new client(%s) by vendor %s connected to %s", str(addr2), str(vendor),
                                str(addr1))
                    # Add client for database, and note rowId
                    row_id = self.db_interface.add_client(addr2, addr1, vendor)
                    # Add client to cache lookup variable
                    self.known_clients.add(addr2)
                    # Call callback funcion on the controller
                    self.network_update_callback({'table': 'Clients', "rowId": row_id})

                if addr2 in self.known_aps and addr1 not in self.known_clients:
                    vendor = self._get_mac_vendor(addr1)
                    logger.info("Discovered new client(%s) by vendor %s connected to %s", str(addr1), str(vendor),
                                str(addr2))
                    # Add client to database, and note rowId
                    row_id = self.db_interface.add_client(addr1, addr2, vendor)
                    # Add client to cache lookup variable
                    self.known_clients.add(addr1)
                    # Call callback funcion on the controller
                    self.network_update_callback({'table': 'Clients', "rowId": row_id})

    # least-significant bit of the most significant byte of the address
    # 0: unicast
    # 1: multicast
    @staticmethod
    def _is_unicast(addr):
        msb = int(addr[0:2], 16)
        if not msb & 1:
            logger.info("%s is unicast ", str(addr))
        else:
            logger.info("%s is NOT unicast ", str(addr))
        return not msb & 1

    # second-least-significant bit of the most significant byte of the address
    # 0: globally unique (OUI enforced)
    # 1: locally administered
    @staticmethod
    def _is_locally_administered(addr):
        msb = int(addr[0:2], 16)
        return (msb >> 1) & 1

    def _get_mac_vendor(self, addr):
        if self._is_locally_administered(addr):
            return "Random"
        try:
            return self.mac_lookup.lookup(addr)
        except VendorNotFoundError:
            return "Unknown"

    @staticmethod
    def _parse_pmf_config(beacon):
        dot11elt = beacon.getlayer(Dot11Elt)
        # Itterate through layers to get RNS IE layer
        while dot11elt and dot11elt.ID != 48:
            dot11elt = dot11elt.payload.getlayer(Dot11Elt)
        # If RNS information IE is found, continue
        if dot11elt is not None and dot11elt.ID == 48:
            rsne = dot11elt.info
            # Start after RSN version field
            cur = 2
            # If next field is Group Data Cipher Suite, skip it
            cipher = int.from_bytes(rsne[cur:cur + 3], byteorder='big')
            if cipher == 0x000fac:
                cur += 4
            # Skip though Pairwise Cipher Suite and AKM Suite
            for _ in range(2):
                # Check if next field is a counter, by checking next bytes OUI
                cipher = int.from_bytes(rsne[cur + 2:cur + 5], byteorder='big')
                if cipher == 0x000fac:
                    suite_counter = int.from_bytes(rsne[cur:cur + 2], byteorder='little')
                    # Skip Count field
                    cur += 2
                    # Skip Suite List
                    cur += 4 * suite_counter
            rns_capabilities = int.from_bytes(rsne[cur:cur + 2], byteorder='little')
            # Extract management frame protection required tag
            mfpr = rns_capabilities >> 6 & 1
            # Extract management frame protection capable tag
            mfpc = rns_capabilities >> 7 & 1
            if mfpr:
                return 2
            elif mfpc:
                return 1
            else:
                return 0
        else:
            # If security is OPEN or WEB, then PMF is disabled, and RNS capabilities missing
            beacon_info = beacon[Dot11Beacon].network_stats()
            security = ', '.join(beacon_info['crypto'])
            if security == "OPN" or security == "WEP":
                return 0
        return -1

    @staticmethod
    def _freq_to_channel(freq):
        lookup_table = {2412: 1, 2417: 2, 2422: 3, 2427: 4, 2432: 5, 2437: 6, 2442: 7, 2447: 8, 2452: 9, 2457: 10,
                        2462: 11, 2467: 12, 2472: 13, 2484: 14, 5075: 15, 5080: 16, 5085: 17, 5090: 18, 5100: 20,
                        5120: 24, 5140: 28, 5160: 32, 5180: 36, 5200: 40, 5220: 44, 5240: 48, 5260: 52, 5280: 56,
                        5300: 60, 5320: 64, 5340: 68, 5360: 72, 5380: 76, 5400: 80, 5420: 84, 5440: 88, 5460: 92,
                        5480: 96, 5500: 100, 5520: 104, 5540: 108, 5560: 112, 5580: 116, 5600: 120, 5620: 124,
                        5640: 128, 5660: 132, 5680: 136, 5700: 140, 5720: 144, 5745: 149, 5765: 153, 5785: 157,
                        5805: 161, 5825: 165, 5845: 169, 5865: 173, 5885: 177}
        return lookup_table[freq]
