import mysql.connector
import json

class NetworkFetcher:

    def __init__(self, db_config):
        self.host = db_config['host']
        self.user = db_config['username']
        self.password = db_config['password']
        self.database = db_config['database']

    def _connect_to_db(self):
        mydb = mysql.connector.connect(
            host = self.host,
            user = self.user,
            password = self.password,
            database = self.database)
        cur = mydb.cursor(dictionary=True)
        return (mydb,cur)

    def _get_vendor(self,vendor,device_type):
        match vendor:
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
                if device_type == "AP":
                    return "../static/img/ap_logo.svg"
                else:
                    return "../static/img/client_logo.svg"

    def _get_ssid_nodes(self,c,row_filter="%"):
        ''' Returns all SSIDs as nodes '''
        c.execute("SELECT DISTINCT ssid FROM APs WHERE id LIKE ""%s""",(str(row_filter),))
        nodes = [dict(id=row['ssid'],label=row['ssid'],group="ssid") for row in c.fetchall()]
        return nodes

    def _get_ap_nodes(self,c,row_filter="%"):
        ''' Returns all APs as nodes '''
        c.execute("SELECT bssid,vendor,channel,security,pmf FROM APs WHERE id LIKE ""%s""",(str(row_filter),))
        nodes = []
        for row in c.fetchall():
            pmf_state = ""
            match row['pmf']:
                case 0:
                    pmf_state = "Disabled"
                case 1:
                    pmf_state = "Optional"
                case 2:
                    pmf_state = "Required"
            title = row['bssid']+"\n"+row['vendor']+"\nChannel:"+str(row['channel'])+"\n"+row['security']+"\nPMF:"+pmf_state
            nodes.append(dict(id=row['bssid'],title=title,group="ap",shape="circularImage",image=self._get_vendor(row['vendor'],"AP")))
        return nodes

    def _get_client_nodes(self,c,rowFilter="%"):
        ''' Returns all Clients as nodes '''
        c.execute("SELECT macaddr,vendor FROM Clients WHERE id LIKE ""%s""",(str(rowFilter),))
        nodes = [dict(id=row['macaddr'],title=row['macaddr']+"\n"+row['vendor'],group="client",shape="circularImage",image=self._get_vendor(row['vendor'],"Client")) for row in c.fetchall()]
        return nodes

    def _get_ap_ssid_edge(self,c,rowFilter="%"):
        ''' Returns all edges between APs and SSIDs '''
        c.execute("SELECT bssid,ssid FROM APs WHERE id LIKE ""%s""",(str(rowFilter),))
        edges = [dict([("from",row['bssid']),("to",row['ssid'])]) for row in c.fetchall()]
        return edges

    def _get_client_ap_edge(self,c,rowFilter="%"):
        ''' Returns all edges between clients and APs '''
        c.execute("SELECT macaddr,bssid FROM Clients WHERE id LIKE ""%s""",(str(rowFilter),))
        edges = [dict([("from",row['macaddr']),("to",row['bssid'])]) for row in c.fetchall()]
        return edges

    def _get_nodes(self,c):
        ''' Returns all nodes(SSIDs,APs,Clients) '''
        return self._get_ssid_nodes(c)+self._get_ap_nodes(c)+self._get_client_nodes(c)

    def _get_edges(self,c):
        ''' Returns all edges(SSID<->APs,APs<->Clients) '''
        return self._get_ap_ssid_edge(c)+self._get_client_ap_edge(c)

    def get_network(self):
        ''' Returns entire network as nodes and edges '''
        mydb,cur = self._connect_to_db()
        network_data = dict([("nodes",self._get_nodes(cur)),("edges",self._get_edges(cur))])
        mydb.close()
        return json.dumps(network_data)

    def get_new_data(self,table,row):
        ''' 
        Returns edges and nodes relevant for the 
        row specifed in the table specified
        Params:
            Table: name of table APs/Clients
            Row: id value of row
        '''
        mydb,cur = self._connect_to_db()

        new_nodes = []
        new_edges = []

        if table == "APs":
            # If the SSID of the new AP is unique, then add to nodes variable
            cur.execute("SELECT COUNT(*),ssid FROM APs WHERE ssid=(SELECT ssid FROM APs WHERE id=%s) AND id<=%s",(str(row),str(row),))
            result = cur.fetchall()[0]
            ssid = result['ssid']
            ssid_count = result['COUNT(*)']
            if int(ssid_count) == 1:
                new_nodes += [dict(id=ssid,label=ssid,group="ssid")]
            # Add AP node and edge between AP and SSID
            new_nodes += self._get_ap_nodes(cur,row)
            new_edges += self._get_ap_ssid_edge(cur,row)
        if table == "Clients":
            # Add client node and edge between client and AP
            new_nodes += self._get_client_nodes(cur,row)
            new_edges += self._get_client_ap_edge(cur,row)
        mydb.close()
        return dict([("nodes",new_nodes),("edges",new_edges)])
