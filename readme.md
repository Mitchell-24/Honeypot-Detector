# Honeypot Detector

Program to detect if a host is a honeypot by checking for known honeypot fingerprint signatures. Signatures are elicited from hosts by communicating with them on specific protocols and analysing the responses for known fingerprints (signatures). The detector has been specifically created to detect Industrial Control System (ICS) honeypots and can detect signatures for 11 protocols on 5 different honeypots. These are:

- [Conpot](https://github.com/mushorg/conpot)
  
  - S7 protcol
  
  - IEC104 protocol
  
  - IPMI protocol
  
  - Modbus protocol
  
  - Bacnet protocol
  
  - ENIP protocol
  
  - SNMP protocol

- [Gaspot](https://github.com/sjhilt/GasPot)
  
  - ATG protocol

- [DNP3pot](https://github.com/referefref/dnp3pot-python3)
  
  - DNP3 protocol

- [Dicompot](https://github.com/nsmfoo/dicompot)
  
  - Dicom protocol

- [Medpot](https://github.com/schmalle/medpot)
  
  - HL7 protocol

## Requirements

- Python 3.13
- nmap
- ipmitool

Also install all Python dependencies listed in `requirements.txt`.

## Usage

To start the detection on one host, simply run:

```bash
python src/main.py [ip-address]
```

The detector will then test if the known ICS ports are open and test for signatures on the open ports.

To also scan all other ports on a host, run the program with the `-s` flag. Note that this make take a very long time or fail altogether. 

```bash
python src/main.py -s [ip-address]
```

### Censys data

The Honeypot Detector can be run on a list of hosts retrieved from Censys.  This is done by using the `-c` option and passing the program the Censys data as a JSON file. In this mode, the detector will scan many hosts in parallel and use the open ports listed in the file to determine what signatures will be tested.

```bash
python src/main.py -c [path/to/data.json]
```

The results will be written into the new `./output` directory.

### IPInfo

The program uses the IPInfo.io API to gather additional information about target hosts, including:

- Hostname (if available)
- City and Region
- Country
- Organization/ASN
- Timezone

To get the most out of IPInfo and avoid rate limiting:

1. Sign up for an API key at [ipinfo.io](https://ipinfo.io)

2. Set the environment variable before running:
   
   ```bash
   export IPINFO_API_KEY='your_api_key_here'
   ```

If no API key is provided, the program will still work but requests may be throttled. 

## Adding new signatures

You can add a new signature by creating a new python file with the name `honeypot_protocol`. Put all your logic for testing the signature in the file and implement the following:

- Make sure the module implements the function `test(address)` which returns True if the signature can be elicited from the host, and False otherwise.

- Add the `@func_set_timeout(10)` annotation above the test function to ensure it never gets stuck.

- In `honeypot_detector.py`, add an entry for the protocol with the port and name to `is_ICS_port()` in the same format  as the other entries.

- If you use a new honeypot, add a new function named `test_HONEYPOT(self)` to `honeypot_detector.py`. Also add a call to this function in `main.py`. 

- In `honeypot_detector.py`, add a new entry for the signature in the test function corresponding to the honeypot in the same format as the other entries. At the bottom of the function, add the signature's result boolean to the if-statement.

- In the `test_all()` function in `honeypot_detector.py`, add an entry for the signature in the same format as the other entries. At the bottom of the function, add an entry in the result dictionary for a new honeypot or append  the signature's result boolean to an existing honeypot entry. 

## Contributors

The Honeypot Detector has been created by five CS master students at [TU Delft](https://www.tudelft.nl/):

- [Arul Agrawal](mailto:a.agrawal-15@student.tudelft.nl)

- [Andrea Malnati](mailto:a.malnati@student.tudelft.nl)

- [Mitchell van Pelt](mailto:m.vanpelt-1@student.tudelft.nl)

- [Mrityunjaya Palanimurugan Vasanthakumari](mailto:m.palanimuruganvasanthakumari@student.tudelft.nl)

- [Erin Vergeer](mailto:e.vergeer@student.tudelft.nl)
