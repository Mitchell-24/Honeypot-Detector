import socket

from func_timeout import func_set_timeout


@func_set_timeout(10)
def test(address):
    """
   Tests if the host has the Conpot Modbus configuration signature implementation signature.
   :param address: The IP address of the host.
   :return: True if the signature is found, False otherwise.
   """
    port = 502

    # Get device information.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((address, port))
    s.sendall(bytes.fromhex("00 01 00 00 00 06 01 2b 00 02 00 01"))
    data = s.recv(1024)
    response = str(data)

    # Check if device info contains known valaues
    device_info = "Siemens" in response and "SIMATIC" in response and "S7-200" in response
    imei_type = data[8] == 14
    conformity_level = data[10] == 1

    # Check if read function always returns the same value.
    if device_info and imei_type and conformity_level:
        s.sendall(bytes.fromhex("00 01 00 00 00 06 01 01 00 01 00 01"))
        data2 = s.recv(1024)
        return data2[:-1] == bytes.fromhex("00 01 00 00 00 04 01 01 01")
    return False