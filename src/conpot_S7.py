import time
import socket

from func_timeout import func_set_timeout


@func_set_timeout(10)
def test_configuration_signature(address):
    """
   Tests if the host has the Conpot S7 configuration signature.
   :param address: The IP address of the host.
   :return: True if the signature is found, False otherwise.
   """
    port = 102
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((address, port))

    # Handshake part 1.
    s.send(bytes.fromhex('03 00 00 16 11 e0 00 00 00 01 00 c0 01 0a c1 02 01 00 c2 02 01 01'))
    data = s.recv(1024)
    time.sleep(0.05)

    # Handshake part 2.
    s.send(bytes.fromhex('03 00 00 19 02 f0 80 32 01 00 00 00 00 00 08 00 00 f0 00 00 01 00 01 01 e0'))
    data2 = s.recv(1024)
    time.sleep(0.05)

    # Diagnostics function.
    s.send(bytes.fromhex(
        '03 00 00 21 02 f0 80 32 07 00 00 01 00 00 08 00 08 00 01 12 04 11 44 01 00 ff 09 00 04 00 1c 00 00'))
    data3 = s.recv(1024)

    s.close()

    # Signature is present if the host's configuration includes these exact values.
    if "Mouser Factory" in str(data3) and "88111222" in str(data3):
        return True
    return False


@func_set_timeout(10)
def test_implementation_signature(address):
    """
   Tests if the host has the Conpot S7 partial implementation signature.
   :param address: The IP address of the host.
   :return: True if the signature is found, False otherwise.
   """
    port = 102
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((address, port))

    # Handshake part 1.
    s.send(bytes.fromhex('03 00 00 16 11 e0 00 00 00 01 00 c0 01 0a c1 02 01 00 c2 02 01 01'))
    data = s.recv(1024)
    time.sleep(0.05)

    # Handshake part 2.
    s.send(bytes.fromhex('03 00 00 19 02 f0 80 32 01 00 00 00 00 00 08 00 00 f0 00 00 01 00 01 01 e0'))
    data2 = s.recv(1024)
    time.sleep(0.05)

    # Diagnostics function, should work.
    s.send(bytes.fromhex(
        '03 00 00 21 02 f0 80 32 07 00 00 01 00 00 08 00 08 00 01 12 04 11 44 01 00 ff 09 00 04 00 1c 00 00'))
    data3 = s.recv(1024)

    # Check that the response follows the S7 protocol.
    if not bytes.fromhex("32 07 00 00 01 00") in data3:
        return False

    # Read function, should not work and cause connection to be closed.
    s.send(bytes.fromhex(
        '03 00 00 1f 02 f0 80 32 01 00 00 01 00 00 0e 00 00 04 01 12 0a 10 02 00 01 00 00 83 00 00 00'))
    data4 = s.recv(1024)

    # Diagnostic function again, should not work because the connection is now closed.
    s.send(bytes.fromhex(
        '03 00 00 21 02 f0 80 32 07 00 00 01 00 00 08 00 08 00 01 12 04 11 44 01 00 ff 09 00 04 00 1c 00 00'))
    data5 = s.recv(1024)

    s.close()

    # Signature is present if at first the diagnostics function returns a response,
    # but the connection is closed after sending the read function.
    if len(data3) != 0 and len(data4) == 0 and len(data5) == 0:
        return True
    return False
