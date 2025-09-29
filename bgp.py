import socket
import struct
from time import sleep

BGP_PORT = 179
BGP_VERSION = 4
MY_AS = 65100
HOLD_TIME = 90
ROUTER_ID = "2.2.2.2"

def ip_to_bytes(ip):
    return bytes(map(int, ip.split(".")))

def build_open_message():
    # BGP OPEN message format
    # Marker (16 bytes) + Length (2 bytes) + Type (1 byte) + Version (1 byte) + AS (2 bytes)
    # + Hold Time (2 bytes) + BGP Identifier (4 bytes) + Optional Parameters Length (1 byte)
    
    marker = b'\xff' * 16
    msg_type = 1  # OPEN
    version = BGP_VERSION
    my_as = MY_AS
    hold_time = HOLD_TIME
    bgp_id = ip_to_bytes(ROUTER_ID)
    opt_len = 0

    payload = struct.pack('!BHH4sB', version, my_as, hold_time, bgp_id, opt_len)
    length = 19 + len(payload)  # 16 marker + 2 length + 1 type + payload
    header = marker + struct.pack('!HB', length, msg_type)

    return header + payload

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('127.0.0.1', BGP_PORT))
        print("[*] Connected to FRR BGP on port 179")

        open_msg = build_open_message()
        s.sendall(open_msg)
        print("[*] OPEN message sent")

        # получаем ответ (OPEN или KEEPALIVE)
        data = s.recv(1024)
        print("[*] Received:", data.hex())

if __name__ == "__main__":
    main()
