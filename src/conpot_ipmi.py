from subprocess import run

from func_timeout import func_set_timeout


@func_set_timeout(10)
def test(address):
    """
   Tests if the host has the Conpot IPMI configuration implementation signature.
   :param address: The IP address of the host.
   :return: True if the signature is found, False otherwise.
   """
    cmd_info = f"ipmitool -I lanplus -H {address} -p 623 -C3 -U Administrator -P Password mc info"
    info = run(cmd_info, shell=True, capture_output=True, timeout=5).stdout

    info = list(map(lambda x: " ".join(x.split()), str(info, "UTF-8").split("\n")))

    # Check that the following configuration is present.
    device_id = "Device ID : 37" in info
    device_revision = "Device Revision : 3" in info or "Device Revision : 19" in info #Hardcoded 0x13, but ipmitool returns 3
    ipmi_version = "IPMI Version : 2.0" in info or "IPMI Version : 2" in info #Hardcoded as 2, but ipmitool returns 2.0
    manufacturer_id = "Manufacturer ID : 15" in info
    if device_id and device_revision and ipmi_version and manufacturer_id:
        return True
    return False