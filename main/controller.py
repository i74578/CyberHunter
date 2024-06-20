""" This module is the controller for the sniffer/deauth component """
import socketio
from logging_config import setup_logger
from db_interface import dbInterface
from deauther import Deauther
from sniffer import Sniffer
from channel_hopper import ChannelHopper
import if_config as if_config

logger = setup_logger(__name__)

INTERFACES = ["wlx5c628b4b9725","wlx5c628b4ba281","wlx5c628b4b90ba"]
CHANNELS = [1,2,3,4,5,6,7,8,9,10,11,12,13,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140]
DB_CONFIG = {"host":"localhost","username":"admin","password":"P7Jyd3A32t","database":"network"}
db_interface = dbInterface(DB_CONFIG)
sio = socketio.Client()
running_procs = []

def emit_network_update_msg(data):
    sio.emit("networkUpdate",data,namespace="/backendConnection")

@sio.on('setMode',namespace='/backendConnection')
def on_set_mode(data):
    '''This function receives the requested mode, and passes it to the NetHunter module'''
    print('Set Mode:' + str(data))
    
    #global running_procs
    for running_proc in running_procs:
        running_proc.stop()

    mode = data['mode']
    if mode == "sniff":
        logger.info("Starting to sniff")
        db_interface.clear_db()
        channel_hopper = ChannelHopper(INTERFACES,CHANNELS)
        channel_hopper.start()
        running_procs.append(channel_hopper)
        sniffer = Sniffer(db_interface,INTERFACES,emit_network_update_msg)
        sniffer.start()
        running_procs.append(sniffer)

    elif mode == "deauth_attack":
        logger.info("Starting deauth attack against %s",data['target'])
        deauther = Deauther(db_interface,INTERFACES,data['target'],"deauth_attack")
        deauther.start()
        running_procs.append(deauther)

    elif mode == "csa_attack":
        logger.info("Starting CSA attack against %s",data['target'])
        deauther = Deauther(db_interface,INTERFACES,data['target'],"csa_attack")
        deauther.start()
        running_procs.append(deauther)

    elif mode == "idle":
        logger.info("Set idle mode")

if __name__ == '__main__':
    if_config.setMonitorMode(INTERFACES)
    db_interface.clear_db()
    sio.connect('http://localhost:5000', namespaces=['/backendConnection'])
    sio.wait()