import socket
import struct
import sys
from .vendor_ids import VENDOR_ID


# BACnet property codes
QUERY_CODES = {
    'firmware': 0x2c,
    'application': 0x0c,
    'model': 0x46,
    'object': 0x4d,
    'object_id': 0x4b,
    'description': 0x1c,
    'location': 0x3a,
    'vendor': 0x79,
    'vendor_id': 0x78,
}

def vendor_lookup(vennum):
    return f"{VENDOR_ID.get(vennum, 'Unknown Vendor Number')} ({vennum})"

def send_query(sock, addr, prop_id):
    # Craft BACnet "read property" query packet
    # This is a direct translation of the Lua string.pack call
    packet = struct.pack(
        '>BBHBBBBBBBIBB',
        0x81,  # Type: BACnet/IP (Annex J)
        0x0a,  # Function: Original-Unicast-NPDU
        0x0011,  # BVLC-Length: 17 bytes
        0x01,  # Version: 0x01 (ASHRAE 135-1995)
        0x04,  # Control (expecting reply)
        0x00,  # APDU Type: Confirmed-REQ, PDU flags: 0x0
        0x05,  # Max response segments unspecified, Max APDU size: 1476 octets
        0x01,  # Invoke ID: 1
        0x0c,  # Service Choice: readProperty
        0x0c,  # Context-specific tag, number 0, Length Value Type 4
        0x023fffff,  # Object Type: device; instance number 4194303
        0x19,  # Context-specific tag, number 1, Length Value Type 1
        prop_id  # Property Identifier
    )
    sock.sendto(packet, addr)

def field_size(packet):
    # Parse field size and encoding from BACnet response
    # This closely follows the NSE logic
    value = packet[17]
    if value % 0x10 < 5:
        length = value % 0x10 - 1
        offset = 18
    else:
        length = packet[18] - 1
        offset = 19
    charset = packet[offset]
    info = packet[offset+1:offset+1+length]
    if charset == 0:  # UTF-8
        return info.decode('utf-8', errors='replace')
    elif charset == 4:  # UCS-2 big-endian
        return info.decode('utf-16-be', errors='replace')
    else:
        return info.hex()

def standard_query(sock, addr, query_type):
    prop_id = QUERY_CODES[query_type]
    send_query(sock, addr, prop_id)
    try:
        resp, _ = sock.recvfrom(1024)
    except socket.timeout:
        return None
    if resp[0] == 0x81 and resp[6] != 0x50:  # Not error
        return field_size(resp)
    return None

def vendornum_query(sock, addr):
    send_query(sock, addr, QUERY_CODES['vendor_id'])
    try:
        resp, _ = sock.recvfrom(1024)
    except socket.timeout:
        return None
    if resp[0] == 0x81 and resp[6] != 0x50:
        value = resp[17]
        if value == 0x21:
            vendornum = resp[18]
            return vendor_lookup(vendornum)
        elif value == 0x22:
            vendornum = int.from_bytes(resp[18:20], byteorder='big')
            return vendor_lookup(vendornum)
    return None

def discover_bacnet(ip, port=47808):
    addr = (ip, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    # Send initial object_id query
    send_query(sock, addr, QUERY_CODES['object_id'])
    try:
        resp, _ = sock.recvfrom(1024)
    except socket.timeout:
        # print("No response, not a BACnet device or filtered.")
        return
    if resp[0] != 0x81:
        # print("Not a BACnet device.")
        return
    result = {}
    if resp[6] == 0x50:
        # print("BACnet ADPU Type: Error (5)")
        # print(resp.hex())
        return
    # Instance Number (object number)
    instance = int.from_bytes(resp[19:22], byteorder='big')
    result["Object-identifier"] = instance
    result["Vendor ID"] = vendornum_query(sock, addr)
    result["Vendor Name"] = standard_query(sock, addr, "vendor")
    result["Firmware"] = standard_query(sock, addr, "firmware")
    result["Application Software"] = standard_query(sock, addr, "application")
    result["Object Name"] = standard_query(sock, addr, "object")
    result["Model Name"] = standard_query(sock, addr, "model")
    result["Description"] = standard_query(sock, addr, "description")
    result["Location"] = standard_query(sock, addr, "location")
    sock.close()
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 bacnet.py <ip> [port]")
        sys.exit(1)
    ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 47808
    result = discover_bacnet(ip, port)
    print("BACnet Device Information:")
    for k, v in result.items():
        print(f"{k}: {v}")
