import math
import time
import ifConfig
import threading

from logging_config import setup_logger
logger = setup_logger(__name__)

class ChannelHopper:
    def __init__(self,interfaces,channels):
        self.interfaces = self._distribute_interface_channels(interfaces,channels)
        self.stop_event = threading.Event()
        self.threads = []


    def _distribute_interface_channels(self,interfaces,channels):
        result = {}
        cpi = math.floor(len(channels)/len(interfaces))
        for i,interface in enumerate(interfaces):
            result[interface] = channels[-cpi*i:] + channels[:-cpi*i]
        return result


    def start(self):
        self.stop_event.clear()
        for interface in self.interfaces:
            th = threading.Thread(target=self._channel_hopper_thread,args=(interface,self.interfaces[interface]))
            th.daemon = True
            th.name = "ChannelHopper:" + interface
            self.threads.append(th)
            th.start()
        logger.debug("Channel hopper: started")

    def _channel_hopper_thread(self,interface,channels,delay=0.5):
        chanIndex = -1
        while not self.stop_event.is_set():
            chanIndex = (chanIndex + 1) % len(channels)
            ifConfig.setChannel(interface,channels[chanIndex])
            logger.debug(str(interface) + ' : Channel set to: ' + str(channels[chanIndex]))
            time.sleep(delay)
        logger.debug(str(interface) + ' : Committing Suicide ')
        
    def stop(self):
        self.stop_event.set()
        for thread in self.threads:
            thread.join()
        self.threads = []
        logger.debug("Channel hopper: stopped")
