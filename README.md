# About The Project
This project is made as a project in course 34229 at DTU.

The program sniffs network traffic using a single or multiple network cards in monitor mode. By analyzing bacon,block ack,RTS and data frames, information about all nearby networks and clients is gathered and stored in a mariaDB database. 
This project also aims to test deauthentication attacks. By double tapping on a client node on the diagram, a deauthentication attack is performed against the client and all APs on the same SSID. This is to prevent the client, conencting on a different channel and getting stable connection. 
By double tapping on an AP, a channel switch annoncement attack is performed. The main benefit of th CSA DoS attack is that it also works against APs using PMF(802.11w). The drawback is that it does not work against all devices. Our testing showed that it worked against almost all apple devices, and for android and windows devies, it was very dependant on the network card model.
![image](https://github.com/i74578/DTU-34229-Deauther/assets/26153040/8c2cc6a0-0fd0-4d1e-a89b-9732a0e8bc22)

# Prerequisites
- One or more network cards supporting monitor mode is required.
- A mariadb database with the following tables is required:
```
CREATE TABLE `APs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `bssid` varchar(12) NOT NULL,
  `vendor` varchar(255) NOT NULL,
  `ssid` varchar(32) NOT NULL,
  `channel` int(11) NOT NULL,
  `security` varchar(32) DEFAULT NULL,
  `pmf` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id` (`id`),
  UNIQUE KEY `mac` (`bssid`)
)

CREATE TABLE `Clients` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `macaddr` varchar(12) NOT NULL,
  `vendor` varchar(255) NOT NULL,
  `bssid` varchar(12) NOT NULL,
  `known_ssids` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id` (`id`),
  UNIQUE KEY `mac` (`macaddr`)
)
```

- The interfaces used for sniffing should be unmanaged by the NetworkManager service. This can be done by adding the following configuration to the networkmanager.conf located at /etc/NetworkManager/
```
[main]
plugins=keyfile

[keyfile]
unmanaged-devices=type:wifi
```

# Installation
```
pip3 install -r requirements.txt
```

# Usage
To use the program:
- Set the config values in the controller.py file
- Run the flask application located in the flask directory
- Run the controller.py file located in the main directory
