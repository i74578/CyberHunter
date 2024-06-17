import mysql.connector

class dbInterface:
    def __init__(self, dbConfig):
        self.host = dbConfig['host']
        self.user = dbConfig['username']
        self.password = dbConfig['password']
        self.database = dbConfig['database']

    def _connectToDB(self):
        mydb = mysql.connector.connect(
            host = self.host,
            user = self.user,
            password = self.password,
            database = self.database)
        cur = mydb.cursor()
        return (mydb,cur)
    
    def add_ap(self, mac, ssid, vendor, channel, security, pmf):
        mydb,cur = self._connectToDB()
        sql = "INSERT INTO APs (mac,ssid,vendor,channel,security,pmf) VALUES (%s,%s,%s,%s,%s,%s)"
        val = (mac,ssid,vendor,channel,security,pmf)
        try:
            cur.execute(sql, val)
            mydb.commit()
        except mysql.connector.errors.IntegrityError as err:
            print("Duplicate")
        mydb.disconnect()
        return cur.lastrowid
    
    def add_client(self,Client,BSSID,vendor):
        mydb,cur = self._connectToDB()
        sql = "INSERT INTO Clients (mac,apmac,vendor) VALUES (%s,%s,%s)"
        val = (Client,BSSID,vendor)
        try:
            cur.execute(sql, val)
            mydb.commit()
        except mysql.connector.errors.IntegrityError as err:
            print("Duplicate")
        mydb.disconnect()
        return cur.lastrowid
    
    def get_associated_ap(self,client):
        mydb,cur = self._connectToDB()
        cur.execute("select apmac from Clients WHERE mac=""%s""",(str(client),))
        rows = cur.fetchall()
        if len(rows) != 1 or len(rows[0]) != 1:
            print("missing")
            return ""
        print("found:"+ rows[0][0])
        mydb.disconnect()
        return rows[0][0]
        
    
    def get_ap_channel(self,ap):
        mydb,cur = self._connectToDB()
        cur.execute("select channel from APs WHERE mac=""%s""",(str(ap),))
        rows = cur.fetchall()
        if len(rows) != 1 or len(rows[0]) != 1:
            print("missing")
            return "0"
        print("found:"+ str(rows[0][0]))
        mydb.disconnect()
        return str(rows[0][0])
    
    def get_client_ssid(self,client):
        mydb,cur = self._connectToDB()
        cur.execute("select APs.SSID FROM Clients INNER JOIN APs ON Clients.apmac = APs.mac WHERE Clients.mac=""%s""",(str(client),))
        rows = cur.fetchall()
        if len(rows) != 1 or len(rows[0]) != 1:
            print("missing")
            return ""
        print("found:"+ str(rows[0][0]))
        mydb.disconnect()
        return str(rows[0][0])
    
    def get_aps_by_ssid(self,ssid):
        mydb,cur = self._connectToDB()
        cur.execute("select mac,channel FROM APs WHERE SSID=""%s"" ORDER BY channel ASC",(str(ssid),))
        rows = cur.fetchall()
        if len(rows) < 0:
            print("missing")
            return ""
        APs = [{'mac':row[0],'channel':row[1]} for row in rows]
        print("found:"+ str(APs))
        mydb.disconnect()
        return APs

    def clear_db(self):
        mydb,cur = self._connectToDB()
        cur.execute("DELETE FROM APs")
        cur.execute("DELETE FROM Clients")
        mydb.commit()
        mydb.disconnect()


