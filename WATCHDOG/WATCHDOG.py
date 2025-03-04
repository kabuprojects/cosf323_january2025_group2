import pyshark
import netifaces
import ipaddress
import json
import base64
import requests

class pckt(object):
    def __init__(self, time_stamp: str = '', ipsrc: str = '', ipdst: str = '', srcport: str = '', dstport: str = '', transport_layer: str = '', highest_layer: str = ''):
        self.time_stamp = time_stamp
        self.ipsrc = ipsrc
        self.ipdst = ipdst
        self.srcport = srcport
        self.dstport = dstport
        self.transport_layer = transport_layer
        self.highest_layer = highest_layer

class apiServer(object):
    def __init__(self, ip:str, port:str):
        self.ip = ip
        self.port = port
server = apiServer('10.96.0.1', '8080')

intF = netifaces.gateways()['default'][netifaces.AF_INET][1]
capture = pyshark.LiveCapture(interface=intF)

def is_api_server(packet: pyshark.packet.packet.Packet, server: apiServer) -> bool:
    '''
    Determine if we are communicating to our reporting WATCHDOG

    Args:
        packet:  capture / pyshark
        server:  apiServer / object

    return True | False if packet communication is reporting to our server 
    '''
    if (hasattr(packet, 'ip') and (hasattr(packet, 'tcp'))):
        if ((packet.ip.src == server.ip) or (packet.ip.dst == server.ip)):
            return True
        else:
            return False


server = apiServer('10.96.0.1 ', '8080')



def is_private_ip(ip_address: str) -> bool:
    '''
    Determines if the given IP is private RFC-1918
    Args:
        ip_address: The ip to check

    Returns:
        True if the ip is private (RFC-1918)
    '''
    ip = ipaddress.ip_address(ip_address)
    return ip.is_private

def report(message: pckt):
    temp = json.dumps(message.__dict__)

    jsonString = temp.encode('ascii')
    b64 = base64.b64encode(jsonString)

    jsonPayload = b64.decode('utf8').replace("'", '"')
    print(jsonPayload)

    try:
        x = requests.get('http://{}:{}/api/?{}'.format(server.ip, server.port, jsonPayload))    
    except ConnectionError as err:
        # do logging to local files TODO:
        pass

def filter(packet: pyshark.packet.packet.Packet):
    '''
    Filters packet on below stuff

    Args:
        packet: The packet from capture
    '''
    # check to see if we are communicating to WATCHDOG
    if is_api_server(packet, server) is True:
        # Bail out
        return

    if hasattr(packet, 'icmp'):
        # We were pinged
        DataGram = pckt()
        DataGram.ipdst = packet.ip.dst
        DataGram.ipsrc = packet.ip.src
        DataGram.highest_layer = packet.ip.highest_layer
        DataGram.time_stamp = packet.sniff_timestamp
        report(DataGram)

    if packet.transport_layer == 'TCP' or packet.transport_layer == 'UDP':
        DataGram = pckt()
        if hasattr(packet, 'ipv6'):
            ''' 
                Bail if ipv6

            '''
            return None
        if hasattr(packet, 'ip'):
            if (is_private_ip(packet.ip.src) is True) and (is_private_ip(packet.ip.dst) is True):
                DataGram.ipsrc = packet.ip.src
                DataGram.ipdst = packet.ip.dst
                DataGram.time_stamp = packet.sniff_timestamp
                DataGram.highest_layer = packet.highest_layer
                DataGram.transport_layer = packet.transport_layer

                if hasattr(packet, 'UDP'):
                    DataGram.dstport = packet.udp.dstport
                    DataGram.srcport = packet.udp.srcport
                if hasattr(packet, 'TCP'):
                    DataGram.dstport = packet.tcp.dstport
                    DataGram.srcport = packet.tcp.srcport
                report(DataGram)
for packet in capture.sniff_continuously():
    filter(packet)