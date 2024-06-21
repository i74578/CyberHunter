import mysql.connector
from logging_config import setup_logger

logger = setup_logger(__name__)

class DbInterface:
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

    def add_ap(self, bssid, ssid, vendor, channel, security, pmf):
        ''' Add AP to database '''
        mydb,cur = self._connect_to_db()
        sql = "INSERT INTO APs (bssid,ssid,vendor,channel,security,pmf) VALUES (%s,%s,%s,%s,%s,%s)"
        val = (bssid,ssid,vendor,channel,security,pmf)
        try:
            cur.execute(sql, val)
            mydb.commit()
        except mysql.connector.errors.IntegrityError:
            logger.info("Failed to add AP:%s, since it is already in the database",bssid)
        mydb.disconnect()
        return cur.lastrowid

    def add_client(self,macaddr,bssid,vendor):
        ''' Add Client to database '''
        mydb,cur = self._connect_to_db()
        sql = "INSERT INTO Clients (macaddr,bssid,vendor) VALUES (%s,%s,%s)"
        val = (macaddr,bssid,vendor)
        try:
            cur.execute(sql, val)
            mydb.commit()
        except mysql.connector.errors.IntegrityError:
            logger.info("Failed to add Client:%s, since it is already in the database",macaddr)
        mydb.disconnect()
        return cur.lastrowid
    
    def get_aps(self,**kwargs):
        ''' 
        Get APs list 
        Params
            BSSID: If provided, returns list of a single AP with a given BSSID
            Client: If provided, returns list of single AP with a given client associated
            SSID: If provided, returns all APs with a given SSID
        '''
        mydb,cur = self._connect_to_db()
        query = ""
        args = ()
        if "bssid" in kwargs:
            query = "SELECT bssid,vendor,ssid,channel,security,pmf from APs WHERE bssid=%s"
            args = (kwargs['bssid'],)
        elif "client" in kwargs:
            query = "SELECT APs.bssid,APs.vendor,APs.ssid,APs.channel,APs.security,APs.pmf FROM Clients INNER JOIN APs ON Clients.macaddr = APs.bssid WHERE Clients.macaddr=%s"
            args = (kwargs['client'],)
        elif "ssid" in kwargs:
            query = "SELECT bssid,vendor,ssid,channel,security,pmf FROM APs WHERE ssid=%s ORDER BY channel ASC"
            args = (kwargs['ssid'],)
        else:
            raise Exception("Invalid parameter")
        cur.execute(query,args)
        results = cur.fetchall()
        print("Result:"+str(results))
        if len(results) < 1:
            raise Exception("Failed to get AP from DB")
        mydb.disconnect()
        return results        

    def get_ap(self,**kwargs):
        ''' Returns the element of the result from the get_aps function '''
        aps = self.get_aps(**kwargs)
        if len(aps) != 1:
            raise Exception("None or more than 1, APs found")
        return aps[0]


    def clear_db(self):
        ''' Clear all rows in the APs and Clients tables in the database '''
        mydb,cur = self._connect_to_db()
        cur.execute("DELETE FROM APs")
        cur.execute("DELETE FROM Clients")
        mydb.commit()
        mydb.disconnect()
