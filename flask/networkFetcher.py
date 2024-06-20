import mysql.connector
import json

def getVendor(Vendor,type):
    match Vendor:
        case "Apple, Inc.": 
            return "../static/img/apple_logo.svg"
        case "Intel Corporate":
            return "../static/img/intel_logo.svg"
        case "Liteon Technology Corporation":
            return "../static/img/liteon_logo.svg"
        case "Cisco Systems, Inc":
            return "../static/img/cisco_logo.svg"
        case "Xiaomi Communications Co Ltd":
            return "../static/img/xiaomi_logo.svg"
        case _:
            if type == "AP":
                return "../static/img/ap_logo.svg"
            else:
                return "../static/img/client_logo.svg"

def _getSSIDnodes(c,rowFilter="%"):
    c.execute("SELECT DISTINCT ssid FROM APs WHERE id LIKE ""%s""",(str(rowFilter),))
    nodes = [dict(id=row[0],label=row[0],group="ssid") for row in c.fetchall()]
    return nodes


def _getAPsnodes(c,rowFilter="%"):
    c.execute("SELECT mac,vendor,channel,security,pmf FROM APs WHERE id LIKE ""%s""",(str(rowFilter),))
    nodes = []
    for row in c.fetchall():
        pmfState = ""
        match row[4]:
            case 0:
                pmfState = "Disabled"
            case 1:
                pmfState = "Optional"
            case 2:
                pmfState = "Required"
        title = row[0]+"\n"+row[1]+"\nChannel:"+str(row[2])+"\n"+row[3]+"\nPMF:"+pmfState
        
        nodes.append(dict(id=row[0],title=title,group="ap",shape="circularImage",image=getVendor(row[1],"AP")))

    return nodes




def _getClientNodes(c,rowFilter="%"):
    c.execute("SELECT mac,vendor FROM Clients WHERE id LIKE ""%s""",(str(rowFilter),))
    nodes = [dict(id=row[0],title=row[0]+"\n"+row[1],group="client",shape="circularImage",image=getVendor(row[1],"Client")) for row in c.fetchall()]
    if rowFilter != "%":
        print("filter set")
        print(nodes)
    return nodes

def _getAPSSIDEdge(c,rowFilter="%"):
    c.execute("SELECT mac,ssid FROM APs WHERE id LIKE ""%s""",(str(rowFilter),))
    edges = [dict([("from",row[0]),("to",row[1])]) for row in c.fetchall()]
    return edges

def _getClientAPEdge(c,rowFilter="%"):
    c.execute("SELECT mac,apmac FROM Clients WHERE id LIKE ""%s""",(str(rowFilter),))
    edges = [dict([("from",row[0]),("to",row[1])]) for row in c.fetchall()]
    return edges

def _getNodes(c):
    return _getSSIDnodes(c)+_getAPsnodes(c)+_getClientNodes(c)

def _getEdges(c):
    return _getAPSSIDEdge(c)+_getClientAPEdge(c)

def getNetwork():
    # Creating connection object
    mydb = mysql.connector.connect(
        host = "localhost",
        user = "admin",
        password = "P7Jyd3A32t",
        database = "network"
    )
    cur = mydb.cursor()
    networkData = dict([("nodes",_getNodes(cur)),("edges",_getEdges(cur))])
    mydb.close()
    return json.dumps(networkData)

def getNewData(table,row):
    # Creating connection object
    mydb = mysql.connector.connect(
        host = "localhost",
        user = "admin",
        password = "P7Jyd3A32t",
        database = "network"
    )
    cur = mydb.cursor()


    newNodes = []
    newEdges = []

    if table == "APs":
        # Check if new SSID
        cur.execute('''SELECT ssid,mac,vendor FROM APs WHERE id = %s''',(str(row),))
        newAP = cur.fetchall()[0]
        SSID = newAP[0]
        cur.execute('''SELECT count(*) FROM APs WHERE ssid = %s''',(str(SSID),))
        SSIDcount = cur.fetchall()[0][0]
        if int(SSIDcount) == 1:
            print("This is a new SSID")
            newNodes += [dict(id=newAP[0],label=newAP[0],group="ssid")]
        #newNodes += [dict(id=newAP[1],title=newAP[1]+"\n"+newAP[2],group=1,shape="circularImage",image=getVendor(newAP[2],"AP"))]
        newNodes += _getAPsnodes(cur,row)
        print(_getAPsnodes(cur,row))
        newEdges += [dict([("from",newAP[1]),("to",newAP[0])])]
    if table == "Clients":
        newNodes += _getClientNodes(cur,row)
        newEdges += _getClientAPEdge(cur,row)
    mydb.close()
    return dict([("nodes",newNodes),("edges",newEdges)])



    



