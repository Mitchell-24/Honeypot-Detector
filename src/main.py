import honeypot_detector
import sys

import censys_batch_processor

if len(sys.argv) < 2:
    print("Please provide the address of the host as an argument.")
    sys.exit(1)
ip_address = sys.argv[-1]

# Process Censys data
if sys.argv[1] == "-c":
    batch_processor = censys_batch_processor.Censys_batch_processor(sys.argv[-1])
    batch_processor.start()
    sys.exit(0)

full_scan = False
if sys.argv[1] == "-s":
    full_scan = True

detector = honeypot_detector.HoneypotDetector(ip_address)
detector.scan_ports(full_scan=full_scan)
detector.test_conpot()
detector.test_gaspot()
detector.test_dnp3pot()
detector.test_dicompot()
detector.test_medpot()