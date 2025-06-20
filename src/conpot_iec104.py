import socket
import time

from func_timeout import func_set_timeout


@func_set_timeout(10)
def test(address):
    """
   Tests if the host has the Conpot IEC104 configuration implementation signature.
   :param address: The IP address of the host.
   :return: True if the signature is found, False otherwise.
   """
    port = 2404
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((address, port))

    # Handshake
    s.send(bytes.fromhex('68 04 07 00 00 00'))
    data = s.recv(1024)
    time.sleep(0.05)

    # Interrogation function
    s.send(bytes.fromhex('68 0e 00 00 00 00 64 01 06 7b ff ff 00 00 00 14'))
    data1 = s.recv(1024)
    time.sleep(0.05)
    data2 = s.recv(1024)
    time.sleep(0.05)
    data3 = s.recv(1024)

    # Check that station address is 7720 and there are 61 stations (59 non-empty) split in specific groups.
    if (data1[10:12] == bytes.fromhex("28 1e") and data1[7] == 1 and data2[7] == 16 and data3[7] == 10
            and data3[59] == 11 and data3[137] == 22 and data3[325] == 1):
        return True
    return False