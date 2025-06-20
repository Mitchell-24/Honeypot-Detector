import socket
import time

from func_timeout import func_set_timeout
from scapy.all import *
from dnp3.DNP3_Lib import (
    DNP3, DNP3ApplicationResponse, DNP3HeaderControl, MASTER, DNP3RequestDataObjects,
    DNP3Transport, DNP3ApplicationRequest, DNP3ApplicationControl
)

TCP_PORT = 20000
TIMEOUT = 5
BANNER_BYTES = bytes.fromhex("05640A00010005003971C0F48200006FBA")  # DNP3 signature

def craft_dnp3_packet(ip, func_code, src=0xCAFE, dst=0x0001, seq=1):
    """
    Crafts a DNP3 packet with the specified function code and adds application objects when needed.
    """
    ctrl = DNP3HeaderControl(DIR=MASTER, PRM=MASTER, FCV=1, FCB=seq & 1, FUNC_CODE_PRI=3)

    pkt = (
        DNP3(
            CONTROL=ctrl,
            DESTINATION=dst,
            SOURCE=src
        ) /
        DNP3Transport(FIR=1, FIN=1, SEQUENCE=seq) /
        DNP3ApplicationRequest(
            Application_control=DNP3ApplicationControl(FIR=1, FIN=1, SEQ=seq),
            FUNC_CODE=func_code
        )
    )

    # Add valid data for READ and WRITE
    if func_code == 1:  # READ: Binary Input, all points
        pkt = pkt / Raw(load=bytes([1, 0, 0x06]))
    elif func_code == 2:  # WRITE: Group 12, Variation 1 (Discrete Output)
        # Qualifier 0x17 (1-octet index), Index 0, Value 0x01
        obj = DNP3RequestDataObjects(Obj=12,Var=1,
                                     IndexPref=1,QualfierCode=0x17)
        pkt = pkt / obj / bytes([1])
    # COLD_RESTART (18) doesn't require any additional data
    # DELAY MEASUREMENT (23) doesn't require any additional data
    return pkt


def send_recv(ip, pkt):
    """
    Sends a single DNP3 packet over TCP and receives the response (if any).
    """
    try:
        with socket.create_connection((ip, TCP_PORT), timeout=TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            s.sendall(bytes(pkt))
            return s.recv(2048)
    except Exception:
        return b''
    
def is_malformed_dnp3_response(raw_bytes: bytes) -> bool:
    """
    Checks if the given raw bytes represent a malformed DNP3 response.
    """
    if len(raw_bytes) < 5 or raw_bytes[0] != 0x05 or raw_bytes[1] != 0x64:
        # print("First two bytes do not match DNP3 protocol signature (05 64)")
        return True
    try:
        pkt = DNP3(raw_bytes)
    except Exception:
        # print("Failed to parse DNP3 packet")
        return True

    if not pkt.haslayer(DNP3ApplicationResponse):
        # print("Packet does not contain a valid DNP3 Application Response layer")
        return True
    function_code = pkt.getlayer(DNP3ApplicationResponse).FUNC_CODE
    if function_code not in (129, 130): 
        # print(f"Function code {function_code} is not a valid DNP3 response code")
        return True
    
    return False


@func_set_timeout(10)
def test(ip: str) -> bool:
    """
    Probes a device over TCP port 20000 with 3 valid DNP3 commands and
    evaluates the responses to determine if the system behaves like a honeypot.
    """
    # List of functions. For now only READ. More non-mutating functions can be added.
    func_codes = [1]
    responses = []

    # Send 3 legitimate DNP3 requests
    for i, code in enumerate(func_codes):
        pkt = craft_dnp3_packet(ip, code, seq=i)
        resp = send_recv(ip, pkt)
        if resp:
            responses.append(resp)
            # print(f"Response for function code {code}: {resp.hex()}")
        time.sleep(1) 

    #If no responses at all → NOT a honeypot
    if not responses:
        # print("No responses received, likely not a honeypot.")
        return False

    # Malfromed response  → honeypot detected
    if any(is_malformed_dnp3_response(r) for r in responses):
        # print("Malformed response detected, likely a honeypot.")
        return True

    # If any response matches known honeypot signature → honeypot detected
    if any(resp == BANNER_BYTES for resp in responses):
        # print("DNP3Pot default signature detected in response.")
        return True
    
    return False
