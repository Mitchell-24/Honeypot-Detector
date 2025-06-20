import asyncio
from subprocess import run
import requests
import conpot_S7
import conpot_bacnet
import conpot_iec104
import conpot_ipmi
import conpot_modbus
import gaspot_atg
import conpot_enip
import os
import dnp3pot_dnp3
import conpot_snmp
import dicompot_DICOM
import medpot_hl7

class HoneypotDetector:

    def __init__(self, host_address):
        """
        Constructs a HoneypotDetector
        :param host_address: the IP address of the target host.
        """
        self.host_address = host_address
        self.open_ports = {}
        self.censys_honeypot_label = False

    def get_host_info(self):
        """
        Retrieves and displays information about the target host using IPInfo.io API.
        Uses bearer token authentication if IPINFO_API_KEY environment variable is set.
        """
        api_key = os.getenv('IPINFO_API_KEY')
        if not api_key:
            print("Warning: IPINFO_API_KEY environment variable not found. API requests may be throttled.")
            response = requests.get(f"https://ipinfo.io/{self.host_address}/json")
        else:
            headers = {'Authorization': f'Bearer {api_key}'}
            response = requests.get(f"https://ipinfo.io/{self.host_address}/json", headers=headers)
        data = response.json()
        
        print("\nTarget Host Information:")
        if 'hostname' in data:
            print(f"Hostname: {data['hostname']}")
        print(f"City: {data.get('city', 'Unknown')}")
        print(f"Region: {data.get('region', 'Unknown')}")
        print(f"Country: {data.get('country', 'Unknown')}")
        print(f"Organization: {data.get('org', 'Unknown')}")
        print(f"Timezone: {data.get('timezone', 'Unknown')}\n")

        return data

    def scan_ports(self, full_scan=False):
        """
        Scans TCP + UDP ports on the host to check if they are open.
        If full scan is set to True, will scan all ports
         and print if the host is a honeypot based on the number of open ports.
        """
        # Get information about the target host
        self.get_host_info()

        udp_test = run("nmap -sU -p 1 localhost", shell=True, capture_output=True, timeout=120).stdout
        udp_privileged = len(udp_test) != 0

        # Do a full port scan if required, otherwise only the ICS ports.
        if full_scan:
            self.full_TCP_scan()
            if udp_privileged:
                self.full_UDP_scan()
            else:
                print("Could not scan UDP ports. Please re-run with root permissions.")
        else:
            self.scan_only_ICS(udp_privileged)

        # Count the number of open ports and print the ones that are found to be open.
        count = 0
        ports = self.open_ports.keys()
        for port in ports:
            if self.open_ports[port]:
                count += 1
                is_ICS, name = self.is_ICS_port(port)
                if is_ICS:
                    print("Found open port " + port + ": " + name + " protocol.")
                else:
                    print("Found open port " + port)

        # Determine the likelihood of the host being a honeypot based on the open ports, only if we scanned all.
        if full_scan:
            if count > 30:
                print("The host has " + str(count) + " ports open. Based on this, it is likely that the host is a honeypot")
            elif count > 10:
                print("The host has " + str(count) + " ports open. Based on this, it is possible that the host is a honeypot")
            else:
                print("The host has " + str(count) + " ports open. Based on this, it is unlikely that the host is a honeypot")

    def full_TCP_scan(self):
        """
        Scans all TCP ports with NMAP.
        """
        cmd_TCP_10000 = "nmap -sT -p 1-10000 " + self.host_address
        cmd_TCP_20000 = "nmap -sT -p 10000-20000 " + self.host_address
        cmd_TCP_30000 = "nmap -sT -p 20000-30000 " + self.host_address
        cmd_TCP_40000 = "nmap -sT -p 30000-40000 " + self.host_address
        cmd_TCP_50000 = "nmap -sT -p 40000-50000 " + self.host_address
        cmd_TCP_60000 = "nmap -sT -p 50000-60000 " + self.host_address
        cmd_TCP_65535 = "nmap -sT -p 60000-65535 " + self.host_address
        scan_results = []
        print("Scanning all TCP ports on the host...    (this can take up to 5 minutes, or even time-out)")
        scan_results.append(run(cmd_TCP_10000, shell=True, capture_output=True, timeout=120).stdout)
        print("DONE scanning TCP ports 1-10000")
        scan_results.append(run(cmd_TCP_20000, shell=True, capture_output=True, timeout=120).stdout)
        print("DONE scanning TCP ports 10000-20000")
        scan_results.append(run(cmd_TCP_30000, shell=True, capture_output=True, timeout=120).stdout)
        print("DONE scanning TCP ports 20000-30000")
        scan_results.append(run(cmd_TCP_40000, shell=True, capture_output=True, timeout=120).stdout)
        print("DONE scanning TCP ports 30000-40000")
        scan_results.append(run(cmd_TCP_50000, shell=True, capture_output=True, timeout=120).stdout)
        print("DONE scanning TCP ports 40000-50000")
        scan_results.append(run(cmd_TCP_60000, shell=True, capture_output=True, timeout=120).stdout)
        print("DONE scanning TCP ports 50000-60000")
        scan_results.append(run(cmd_TCP_65535, shell=True, capture_output=True, timeout=120).stdout)
        print("DONE scanning TCP ports 60000-65535\n")
        for part in scan_results:
            for line in str(part, "UTF-8").split("\n")[6:-2]:
                if "/" in line:
                    port = line.split("/")[0]
                    self.open_ports["TCP-" + port] = True

    def full_UDP_scan(self):
        """
        Scans all UDP ports with NMAP.
        """
        cmd_UDP_10000 = "nmap -sU -p 1-10000 " + self.host_address
        cmd_UDP_20000 = "nmap -sU -p 10000-20000 " + self.host_address
        cmd_UDP_30000 = "nmap -sU -p 20000-30000 " + self.host_address
        cmd_UDP_40000 = "nmap -sU -p 30000-40000 " + self.host_address
        cmd_UDP_50000 = "nmap -sU -p 40000-50000 " + self.host_address
        cmd_UDP_60000 = "nmap -sU -p 50000-60000 " + self.host_address
        cmd_UDP_65535 = "nmap -sU -p 60000-65535 " + self.host_address
        scan_results = []
        print("Scanning all UDP ports on the host...    (this can take up to 5 minutes or even time-out)")
        scan_results.append(run(cmd_UDP_10000, shell=True, capture_output=True, timeout=120).stdout)
        print("DONE scanning UDP ports 1-10000")
        scan_results.append(run(cmd_UDP_20000, shell=True, capture_output=True, timeout=120).stdout)
        print("DONE scanning UDP ports 10000-20000")
        scan_results.append(run(cmd_UDP_30000, shell=True, capture_output=True, timeout=120).stdout)
        print("DONE scanning UDP ports 20000-30000")
        scan_results.append(run(cmd_UDP_40000, shell=True, capture_output=True, timeout=120).stdout)
        print("DONE scanning UDP ports 30000-40000")
        scan_results.append(run(cmd_UDP_50000, shell=True, capture_output=True, timeout=120).stdout)
        print("DONE scanning UDP ports 40000-50000")
        scan_results.append(run(cmd_UDP_60000, shell=True, capture_output=True, timeout=120).stdout)
        print("DONE scanning UDP ports 50000-60000")
        scan_results.append(run(cmd_UDP_65535, shell=True, capture_output=True, timeout=120).stdout)
        print("DONE scanning UDP ports 60000-65535\n")
        for part in scan_results:
            for line in str(part, "UTF-8").split("\n")[5:-2]:
                if "/" in line:
                    port = line.split("/")[0]
                    self.open_ports["UDP-" + port] = True

    def scan_only_ICS(self, udp_privileged):
        """
        Scans only the known ICS ports.
        :param udp_privileged: Boolean indicating if the process is privileged to run NMAP in UDP mode.
        """
        for port in range(1, 65536):
            tcp_port = "TCP-" + str(port)
            udp_port = "UDP-" + str(port)
            if self.is_ICS_port(tcp_port)[0]:
                command = "nmap -sT -p " + str(port) + " " + self.host_address
                result = run(command, shell=True, capture_output=True, timeout=120).stdout
                for line in str(result, "UTF-8").split("\n")[5:-2]:
                    if "/" in line:
                        self.open_ports[tcp_port] = True
            if self.is_ICS_port(udp_port)[0]:
                if udp_privileged:
                    command = "nmap -sU -p " + str(port) + " " + self.host_address
                    result = run(command, shell=True, capture_output=True, timeout=120).stdout
                    for line in str(result, "UTF-8").split("\n")[5:-2]:
                        if "/" in line:
                            self.open_ports[udp_port] = True
                else:
                    print("Could not test port UDP-" + str(port)
                          + ". Re-run with root permissions to test protocols on UDP ports.")

    def is_ICS_port(self, port):
        """
        Checks if a known ICS protocol uses a port.
        :param port: The type-port combination to be checked.
        :return: Tuple consisting of: True if the port is used by a know ICS protocol, False otherwise,
         and the name of the protocol if True.
        """
        if port == "TCP-102":
            return True, "S7"
        elif port == "TCP-2404":
            return True, "IEC104"
        elif port == "UDP-623":
            return True, "IPMI"
        elif port == "TCP-502":
            return True, "Modbus"
        elif port == "UDP-47808":
            return True, "Bacnet"
        elif port == "TCP-10001":
            return True, "ATG"
        elif port == "TCP-44818":
            return True, "ENIP"
        elif port == "UDP-16100":
            return True, "SNMP"
        elif port == "TCP-20000":
            return True, "DNP3"
        elif port == "TCP-11112":
            return True, "DICOM"
        elif port == "TCP-2575":
            return True, "MedPot"
        return False, ""

    def test_conpot(self):
        """
        Determines if the host is running Conpot based which signatures can be elicited.
        """
        print("\nTesting if the host is a Conpot instance...")

        if "TCP-102" in self.open_ports:
            try: S7_conf = conpot_S7.test_configuration_signature(self.host_address)
            except: S7_conf = False
        else: S7_conf = False
        print("Found S7 configuration signature.") if S7_conf else None

        if "TCP-102" in self.open_ports:
            try: S7_implementation = conpot_S7.test_implementation_signature(self.host_address)
            except: S7_implementation = False
        else: S7_implementation = False
        print("Found S7 partial implementation signature.") if S7_implementation else None

        if "TCP-2404" in self.open_ports:
            try: IEC104 = conpot_iec104.test(self.host_address)
            except: IEC104 = False
        else: IEC104 = False
        print("Found IEC104 signature.") if IEC104 else None

        if "UDP-623" in self.open_ports:
            try: IPMI = conpot_ipmi.test(self.host_address)
            except: IPMI = False
        else: IPMI = False
        print("Found IPMI signature.") if IPMI else None

        if "TCP-502" in self.open_ports:
            try: modbus = conpot_modbus.test(self.host_address)
            except: modbus = False
        else: modbus = False
        print("Found Modbus signature.") if modbus else None

        if "UDP-47808" in self.open_ports:
            try: bacnet = conpot_bacnet.test(self.host_address)
            except: bacnet = False
        else: bacnet = False
        print("Found Bacnet signature.") if bacnet else None

        if "TCP-44818" in self.open_ports:
            try: enip = conpot_enip.test(self.host_address)
            except: enip = False
        else: enip = False
        print("Found ENIP signature.") if enip else None

        if "UDP-16100" in self.open_ports:
            try: snmp = asyncio.run(conpot_snmp.test(self.host_address))
            except: snmp = False
        else: snmp = False
        print("Found SNMP signature.") if snmp else None

        if S7_conf or S7_implementation or IEC104 or IPMI or modbus or bacnet or snmp or enip:
            print("The host is definitely a Conpot instance.")
        else:
            print("Unlikely that the host is a Conpot instance.")
    
    def test_gaspot(self):
        """
        Determines if the host is running Gaspot based on which signatures can be elicited.
        """
        print("\nTesting if the host is a Gaspot instance...")

        if "TCP-10001" in self.open_ports:
            try: atg = gaspot_atg.test_fast(self.host_address)
            except: atg = False
        else: atg = False
        print("Found ATG signature.") if atg else None

        if atg:
            print("The host is definitely a Gaspot instance or Conpot with the guardian_ast template.")
        else:
            print("Unlikely that the host is a Gaspot instance.")

    def test_dnp3pot(self):
        """
        Determines if the host is running DNP3Pot based on which signatures can be elicited.
        """
        print("\nTesting if the host is a DNP3pot instance...")

        if "TCP-20000" in self.open_ports:
            try: dnp3 = dnp3pot_dnp3.test(self.host_address)
            except: dnp3 = False
        else: dnp3 = False
        print("Found DNP3 signature.") if dnp3 else None

        if dnp3:
            print("The host is definitely a DNP3Pot instance.")
        else:
            print("Unlikely that the host is a DNP3Pot instance.")
    
    def test_dicompot(self):
        """
        Determines if the host is running DicomPot based on which signatures can be elicited.
        """
        print("\nTesting if the host is a DicomPot instance...")

        if "TCP-11112" in self.open_ports:
            try: dicom = dicompot_DICOM.test(self.host_address)
            except: dicom = False
        else: dicom = False

        if dicom:
            print("The host is definitely a DicomPot instance.")
        else:
            print("Unlikely that the host is a DicomPot instance.")
            
    def test_medpot(self):
        """
        Determines if the host is running a MedPot (HL7 honeypot) based on which signatures can be elicited.
        """
        print("\nTesting if the host is a MedPot instance...")

        if "TCP-2575" in self.open_ports:
            try: HL7 = medpot_hl7.test(self.host_address)
            except: HL7 = False
        else: HL7 = False
        print("Found HL7 signature.") if HL7 else None

        if HL7:
            print("The host is definitely a MedPot instance.")
        else:
            print("Unlikely that the host is a MedPot instance.")


    def test_all(self):
        """
        Tests for all known signatures if the corresponding port is open.
        :return: A summary of the found signatures and possible honeypots.
        """
        # First check if the host responds to a ping. Unlikely that it is online when no response, so we skip it.
        ping = os.system("ping -c 1 " + self.host_address + " > /dev/null 2>&1")
        if ping != 0:
            return {
                "Ping": False,
                "Host": self.host_address,
                "Ports": sorted(list(set(map(lambda x: int(x[4:]), self.open_ports.keys())))),
            }

        signatures = []
        # Conpot signatures
        if "TCP-102" in self.open_ports:
            try: S7_conf = conpot_S7.test_configuration_signature(self.host_address)
            except: S7_conf = False
        else: S7_conf = False
        if S7_conf: signatures.append("S7-1")

        if "TCP-102" in self.open_ports:
            try: S7_implementation = conpot_S7.test_implementation_signature(self.host_address)
            except: S7_implementation = False
        else: S7_implementation = False
        if S7_implementation: signatures.append("S7-2")

        if "TCP-2404" in self.open_ports:
            try: IEC104 = conpot_iec104.test(self.host_address)
            except: IEC104 = False
        else: IEC104 = False
        if IEC104: signatures.append("IEC104")

        if "UDP-623" in self.open_ports:
            try: IPMI = conpot_ipmi.test(self.host_address)
            except: IPMI = False
        else: IPMI = False
        if IPMI: signatures.append("IPMI")

        if "TCP-502" in self.open_ports:
            try: modbus = conpot_modbus.test(self.host_address)
            except: modbus = False
        else: modbus = False
        if modbus: signatures.append("Modbus")

        if "UDP-47808" in self.open_ports:
            try: bacnet = conpot_bacnet.test(self.host_address)
            except: bacnet = False
        else: bacnet = False
        if bacnet: signatures.append("Bacnet")

        if "TCP-44818" in self.open_ports:
            try: enip = conpot_enip.test(self.host_address)
            except: enip = False
        else: enip = False
        if enip: signatures.append("ENIP")

        if "UDP-16100" in self.open_ports:
            try: snmp = conpot_snmp.test(self.host_address)
            except: snmp = False
        else: snmp = False
        if snmp: signatures.append("SNMP")

        # Gaspot signature
        if "TCP-10001" in self.open_ports:
            try: atg = gaspot_atg.test_fast(self.host_address)
            except: atg = False
        else: atg = False
        if atg: signatures.append("ATG")

        # DNP3Pot signature
        if "TCP-20000" in self.open_ports:
            try: dnp3 = dnp3pot_dnp3.test(self.host_address)
            except: dnp3 = False
        else: dnp3 = False
        if dnp3: signatures.append("DNP3")

        # Dicompot signature
        if "TCP-11112" in self.open_ports:
            try: dicom = dicompot_DICOM.test(self.host_address)
            except: dicom = False
        else: dicom = False
        if dicom: signatures.append("Dicom")

        # Medpot signature
        if "TCP-2575" in self.open_ports:
            try: HL7 = medpot_hl7.test(self.host_address)
            except: HL7 = False
        else: HL7 = False
        if HL7: signatures.append("HL7")

        return {
            "Ping": True,
            "Host": self.host_address,
            "Ports": sorted(list(set(map(lambda x: int(x[4:]), self.open_ports.keys())))),
            "Censys_honeypot_label": self.censys_honeypot_label,
            "Signatures": signatures,
            "Honeypots": {
                "Conpot": S7_conf or S7_implementation or IEC104 or IPMI or modbus or bacnet or enip or snmp,
                "Gaspot": atg,
                "DNP3Pot": dnp3,
                "Dicompot": dicom,
                "Medpot": HL7
            }
        }