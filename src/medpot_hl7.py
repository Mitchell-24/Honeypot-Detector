import socket

from func_timeout import func_set_timeout


# see https://github.com/schmalle/medpot/blob/master/template/dummyok.xml
def signature_found(response):
    signature = """MSH|^~\&|SENDING_APPLICATION|SENDING_FACILITY|RECEIVING_APPLICATION|RECEIVING_FACILITY|20110614075841||ACK|1407511|P|2.3||||
        MSA|AA|1407511|Success||"""
    return signature in response

@func_set_timeout(10)
def test(host_address):
    port = 2575  # Standard HL7/MedPot port
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        
        s.connect((host_address, port))
        
        
        hl7_msg = (
            "MSH|TEST"
        )
        
        s.sendall(hl7_msg.encode())
        
        response = s.recv(4096)
        s.close()
        response_str = response.decode('utf-8', errors='ignore')
        
        is_medpot_response = signature_found(response_str)
        
        if is_medpot_response:
            return True
        else:
            return False
            
    except socket.timeout:
        return False
    except socket.error as e:
        return False
    except Exception as e:
        return False 

if __name__ == "__main__":
    test("127.0.0.1")