"""
This module connects the backend sniffer/deauth component to the frontend site using SocketIO
"""

import json
from flask_socketio import SocketIO, emit
from flask import Flask, render_template
from .network_fetcher import NetworkFetcher

app = Flask(__name__)
sio = SocketIO(app, debug=True)

DB_CONFIG = {"host": "localhost", "username": "admin", "password": "P7Jyd3A32t", "database": "network"}
network_fetcher = NetworkFetcher(DB_CONFIG)


def broadcast_network_update_msg(data):
    """ Forward message about graph update mssage to all clients """
    sio.emit('addToGraph', json.dumps(data))


# On message from client
@sio.on('connect')
def connect():
    """ Fetch entire network graph and send to client after initial connect """
    emit('initGraph', network_fetcher.get_network())


@sio.on("setMode")
def rx_setmode(data):
    """ Forward message about changing mode to the sniffer/deauth """
    if data['mode'] == "sniff":
        sio.emit("clearGraph")
    print("Received setMode: " + str(data))
    sio.emit("setMode", data, namespace="/backendConnection")


# On messages from sniffer/deauther
@sio.on('connect', namespace="/backendConnection")
def sniffer_connect():
    print("Connected to sniffer")


@sio.on('disconnect', namespace="/backendConnection")
def sniffer_disconnect():
    print("Sniffer has disconnected")


@sio.on('networkUpdate', namespace="/backendConnection")
def on_network_update_msg(data):
    """ Forward new data message to all clients """
    new_data = network_fetcher.get_new_data(data['table'], data['rowId'])
    broadcast_network_update_msg(new_data)


@sio.on('modeReady', namespace="/backendConnection")
def mode_ready(data):
    sio.emit("modeReady", "{}")


# Flask endpoints
@app.route("/")
def index():
    return render_template('vis.html')
