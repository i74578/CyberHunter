import sqlite3
import json

con = sqlite3.connect("main.db")
c = con.cursor()

def getSSIDnodes():
    c.execute('''SELECT DISTINCT SSID FROM AP''')
    nodes = [dict(id=row[0],label=row[0],group=4) for row in c.fetchall()]
    return nodes
  
def getAPsnodes():
    c.execute('''SELECT MAC,Vendor FROM AP''')
    nodes = [dict(id=row[0],title=row[0]+"\n"+row[1],group=1) for row in c.fetchall()]
    return nodes

def getClientNodes():
    c.execute('''SELECT MAC,Vendor FROM CLIENT''')
    nodes = [dict(id=row[0],title=row[0]+"\n"+row[1],group=0) for row in c.fetchall()]
    return nodes

def getNodes():
    return getSSIDnodes()+getAPsnodes()+getClientNodes()

def getAPSSIDEdge():
    c.execute('''SELECT MAC,SSID FROM AP''')
    nodes = [dict([("from",row[0]),("to",row[1])]) for row in c.fetchall()]
    return nodes

def getClientAPEdge():
    c.execute('''SELECT MAC,AP FROM CLIENT''')
    nodes = [dict([("from",row[0]),("to",row[1])]) for row in c.fetchall()]
    return nodes

def getEdges():
    return getAPSSIDEdge()+getClientAPEdge()

print(json.dumps(dict([("nodes",getNodes()),("edges",getEdges())])))
