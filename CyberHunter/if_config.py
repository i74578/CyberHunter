import subprocess


def set_monitor_mode(interfaces):
    """
    Set interfaces or interface to monitor mode
    Params:
        Single interface as string or multiple interfaces as list of strings
    """
    if isinstance(interfaces, str):
        interfaces = [interfaces]
    for interface in interfaces:
        print(interface)
        assert 0 == subprocess.call(["sudo", "ip", "link", "set", interface, "down"])
        assert 0 == subprocess.call(["sudo", "iw", interface, "set", "monitor", "fcsfail"])
        assert 0 == subprocess.call(["sudo", "ip", "link", "set", interface, "up"])


def set_channel(interface, c):
    """ Set at interface to a specific 20MHz channel """
    command = ['sudo', 'iw', 'dev', interface, 'set', 'channel', str(c), 'HT20']
    assert 0 == subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
