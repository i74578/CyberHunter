"""
This module connects the backend sniffer/deauth component to the frontend site using SocketIO
"""


import json
import networkFetcher
from flask_socketio import SocketIO, emit
from flask import Flask,render_template



app = Flask(__name__)
sio = SocketIO(app,debug=True)

connected_to_sniffer = False

def broadcast_network_update_msg(data):
    """ Forward message about graph update mssage to all clients """
    sio.emit('addToGraph', json.dumps(data))

# On message from client
@sio.on('connect')
def connect():
    """ Fetch entire network graph and send to client after initial connect """
    emit('initGraph', networkFetcher.getNetwork())

@sio.on("setMode")
def rx_setmode(data):
    """ Forward message about changing mode to the sniffer/deauth """
    if data['mode'] == "sniff" and data['clear']:
        sio.emit("clearGraph")
    print("Received setMode: " + str(data))
    sio.emit("setMode",data,namespace="/backendConnection")


# On messages from sniffer/deauther
@sio.on('connect',namespace="/backendConnection")
def sniffer_connect():
    connected_to_sniffer = True
    print("Connected to sniffer")

@sio.on('disconnect',namespace="/backendConnection")
def sniffer_disconnect():
    connected_to_sniffer = False
    print("Sniffer has disconnected")

@sio.on('networkUpdate',namespace="/backendConnection")
def on_network_update_msg(data):
    """ Forward new data message to all clients """
    newData = networkFetcher.getNewData(data['table'],data['rowId'])
    broadcast_network_update_msg(newData)

# Flask endpoints
@app.route("/")
def index():
    return render_template('Vis.html')