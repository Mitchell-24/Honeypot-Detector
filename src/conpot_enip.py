import sys
import socket
import logging

from func_timeout import func_set_timeout
from scapy.all import raw
from scapy.contrib.enipTCP import ENIPListIdentity, ENIPTCP, ENIPListIdentityItem

ENIP_TCP_PORT = 44818
TIMEOUT = 5 
DEFAULT_PRODUCT_NAME  = "1756-L61/B LOGIX5561"
DEFAULT_SERIAL_NUMBER = 7079450 

def send_recv(ip, pkt):
    try:
        with socket.create_connection((ip, ENIP_TCP_PORT), timeout=TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            s.sendall(raw(pkt))
            return s.recv(2048)
    except Exception as e:
        logging.error(f"Socket error: {e}")
        return b''

def test_list_identity(target_ip):
    enip_header = ENIPTCP(
        commandId=0x0063,   
        length=0,
        session=0,         
        status=0,
        senderContext=0,
        options=0
    )
    pkt = enip_header 
    try:
        raw_resp = send_recv(target_ip, pkt)

        if not raw_resp:
            return False
        resp_pkt = ENIPTCP(raw_resp)
        if ENIPListIdentity not in resp_pkt:
            return False
        list_id_layer = resp_pkt[ENIPListIdentity]
        if not list_id_layer.items:
            return False
        item = list_id_layer[ENIPListIdentityItem]
        item = list_id_layer.items[0]
        serial = item.serialNumber
        raw_pn = item.productName 
        if serial == DEFAULT_SERIAL_NUMBER and raw_pn.decode() == DEFAULT_PRODUCT_NAME:
            return True
        return False
    except Exception as e:
        return False


@func_set_timeout(10)
def test(target_ip):
    return test_list_identity(target_ip)
    
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python conpot_enip.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    test(target_ip)