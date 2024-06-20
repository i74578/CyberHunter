import math
import time
import threading
import if_config as if_config

from logging_config import setup_logger
logger = setup_logger(__name__)

class ChannelHopper:
    ''' Class for channel hopping through channels on multiple network interfaces simultaneously '''
    def __init__(self,interfaces,channels):
        self.interfaces = self._distribute_interface_channels(interfaces,channels)
        self.stop_event = threading.Event()
        self.threads = []


    def _distribute_interface_channels(self,interfaces,channels):
        ''' 
        Return as dict with interface as key and channels list as value
        Params: 
            interfaces at list of strings
            channels as list of integers
    
        Distributes the channels equaly to the list of interface
        '''
        result = {}
        cpi = math.floor(len(channels)/len(interfaces))
        for i,interface in enumerate(interfaces):
            result[interface] = channels[-cpi*i:] + channels[:-cpi*i]
        return result

    def start(self):
        ''' 
        Start the channel hopper which will create and 
        start one channel hopper thread for each interface 
        '''
        self.stop_event.clear()
        for interface, interface_channels in self.interfaces.items():
            th = threading.Thread(target=self._channel_hopper_thread,args=(interface,interface_channels))
            th.daemon = True
            th.name = "ChannelHopper Thread on " + interface
            self.threads.append(th)
            th.start()
        logger.debug("Channel hopper: started")

    def _channel_hopper_thread(self,interface,channels,delay=0.5):
        channel_index = -1
        while not self.stop_event.is_set():
            channel_index = (channel_index + 1) % len(channels)
            if_config.setChannel(interface,channels[channel_index])
            logger.debug('%s : Channel set to: %s',str(interface),str(channels[channel_index]))
            time.sleep(delay)
        logger.debug('%s : Committing Suicide ',str(interface))

    def stop(self):
        ''' Stop the channel hopping threads and wait for them to stop'''
        self.stop_event.set()
        for thread in self.threads:
            thread.join()
        self.threads = []
        logger.debug("Channel hopper: stopped")
