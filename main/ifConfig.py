import subprocess 

def setMonitorMode(interfaces):
    if isinstance(interfaces,str):
        interfaces = [interfaces]
    for interface in interfaces:
        print(interface)
        assert 0 == subprocess.call(["sudo","ip", "link", "set", interface, "down"])
        assert 0 == subprocess.call(["sudo","iw", interface, "set", "monitor", "fcsfail"])
        assert 0 == subprocess.call(["sudo","ip", "link", "set", interface, "up"])

def setChannel(interface,c,b=""):
    command = ['sudo','iw','dev',interface,'set','channel',str(c),'HT20']
    if b:
        command.append(str(b))
    assert 0 == subprocess.call(command,stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
