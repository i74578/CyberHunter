import requests, json


def notifyUpdate(table,row):
    customHeaders = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    response = requests.post('http://127.0.0.1:5000/update',data='{"table":"'+table+'","row":'+str(row)+'}',headers=customHeaders)

notifyUpdate("AP",333)