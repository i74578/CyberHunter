""" This module is the controller for the sniffer/deauth component """
import socketio
from dbInterface import dbInterface
from Deauther import Deauther
from Sniffer import Sniffer
from ChannelHopper import ChannelHopper
import ifConfig

#interfaces = ["wlx5c628b4b9725","wlx5c628b4ba281","wlx5c628b4b90ba"]
interfaces = ["wlx5c628b4ba281","wlx5c628b4b90ba"]
channels = [1,2,3,4,5,6,7,8,9,10,11,12,13,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140]
dbConfig = {"host":"localhost","username":"admin","password":"P7Jyd3A32t","database":"network"}


ifConfig.setMonitorMode(interfaces)

db_interface = dbInterface(dbConfig)

db_interface.clear_db()

running_procs = []

sio = socketio.Client()

def emit_network_update_msg(data):
    sio.emit("networkUpdate",data,namespace="/backendConnection")

@sio.on('setMode',namespace='/backendConnection')
def on_set_mode(data):
    '''This function receives the requested mode, and passes it to the NetHunter module'''
    print('Set Mode:' + str(data))
    
    global running_procs
    for running_proc in running_procs:
        running_proc.stop()

    mode = data['mode']
    if mode == "sniff":
        db_interface.clear_db()
        channel_hopper = ChannelHopper(interfaces,channels)
        channel_hopper.start()
        running_procs.append(channel_hopper)
        sniffer = Sniffer(db_interface,interfaces,emit_network_update_msg)
        sniffer.start()
        running_procs.append(sniffer)

    elif mode == "deauth":
        print("DEAUTH")
        deauther = Deauther(db_interface,interfaces,data['target'],data['entireSSID'])
        deauther.start()
        running_procs.append(deauther)

        
    elif mode == "idle":
        print("IDLE")
            

sio.connect('http://localhost:5000', namespaces=['/backendConnection'])
sio.wait()