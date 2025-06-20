from func_timeout import func_set_timeout
from pysnmp.hlapi.v1arch import next_cmd
from pysnmp.hlapi.v3arch import *

PORT = 161
TIMEOUT = 30
COMMUNITY = 'public'

SIGNATURE_PATTERNS = [
    "Siemens, SIMATIC, S7-200",
    "Siemens AG",
    "CP 443-1 EX40",
    "Venus",
    "72",
    "0",
    "1.3.6.1.4.1.20408"
]

@func_set_timeout(10)
async def test(address):
    """
    Tests whether the given host behaves like a Conpot honeypot.
    :param address: IP or hostname
    :return: True if signature found, False otherwise
    """
    target = await UdpTransportTarget.create((address, PORT))
    count = 0
    errInd, errStat, _, varBinds = await next_cmd(
        SnmpEngine(),
        CommunityData(COMMUNITY, mpModel=1),
        target,
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.1')),
        lexicographicMode=False
    )
    if errInd or errStat:
        return count > 0
    for varBind in varBinds:
        oid, val = varBind
        text = str(val)
        for sig in SIGNATURE_PATTERNS:
            if sig in text:
                count += 1
                break
    return count > 0
    

