# DTU-34229-Deauther

# Prerequisites
The interface used for sniffing should be unmanaged by the NetworkManager service. This can be done by adding the following configuration to the networkmanager.conf located at /etc/NetworkManager/
'''
[main]
plugins=keyfile

[keyfile]
unmanaged-devices=type:wifi
'''
