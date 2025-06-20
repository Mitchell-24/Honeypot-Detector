from func_timeout import func_set_timeout

from bacnet.bacnet_helper import discover_bacnet


# ok so conpot has a certain default configuration for bacnet
# and it is possible to detect it by looking at the fields below
@func_set_timeout(10)
def test(address):
    result = discover_bacnet(address, 47808)

    if (
        result["Vendor ID"] == "Cornell University (15)"
        and result["Vendor Name"] == "Alerton Technologies, Inc."
        and result["Object-identifier"] == 36113
        and result["Object Name"] == "SystemName"
        and result["Model Name"] == "VAV-DD Controller"
    ):
        return True
    return False
