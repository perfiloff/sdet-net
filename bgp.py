import asyncio
import struct
from datetime import datetime

BGP_PORT = 179
BGP_VERSION = 4
MY_AS = 65100
HOLD_TIME = 180
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

def build_keepalive_message():
    marker = b"\xff" * 16
    length = 19
    msg_type = 4  # KEEPALIVE
    return marker + struct.pack("!HB", length, msg_type)

def decode_open_message(data: bytes):
    """
    Декодирует BGP OPEN сообщение.
    На вход подаётся весь пакет (с marker, length, type).
    Возвращает словарь с полями.
    """
    if len(data) < 29:  # 19 заголовок + 10 минимум payload
        raise ValueError("Too short for BGP OPEN")

    # Заголовок
    marker = data[:16]
    length, msg_type = struct.unpack("!HB", data[16:19])

    if marker != b"\xff" * 16:
        raise ValueError("Bad marker")
    if msg_type != 1:
        raise ValueError("Not an OPEN message")

    # Payload
    version, my_as, hold_time, bgp_id, opt_len = struct.unpack("!BHH4sB", data[19:29])
    bgp_id_str = ".".join(map(str, bgp_id))

    # Опциональные параметры
    opts = data[29:29 + opt_len] if opt_len > 0 else b""

    return {
        "length": length,
        "type": msg_type,
        "version": version,
        "my_as": my_as,
        "hold_time": hold_time,
        "bgp_id": bgp_id_str,
        "opt_len": opt_len,
        "opt_bytes": opts.hex() if opts else None,
    }
    
def parse_optional_params(opt_bytes: bytes):
    i = 0
    while i < len(opt_bytes):
        if i + 2 > len(opt_bytes):
            print("[!] Truncated optional param header")
            break
        param_type, param_len = struct.unpack("!BB", opt_bytes[i:i+2])
        param_value = opt_bytes[i+2:i+2+param_len]
        i += 2 + param_len

        print(f"    - Optional Param: type={param_type}, length={param_len}")

        # Capability
        if param_type == 2:
            j = 0
            while j < len(param_value):
                if j + 2 > len(param_value):
                    print("      [!] Truncated capability header")
                    break
                cap_code, cap_len = struct.unpack("!BB", param_value[j:j+2])
                cap_value = param_value[j+2:j+2+cap_len]
                j += 2 + cap_len

                print(f"      * Capability: code={cap_code}, length={cap_len}, value={cap_value.hex()}")


def decode_keepalive_message(data: bytes):
    if len(data) < 19:
        raise ValueError("Сообщение слишком короткое для BGP")

    marker, length, msg_type = struct.unpack("!16sHB", data[:19])

    if marker != b"\xff" * 16:
        raise ValueError("Неверный маркер")

    if length != 19:
        raise ValueError(f"KEEPALIVE должен быть длиной 19, получено {length}")

    if msg_type != 4:
        raise ValueError(f"Это не KEEPALIVE (тип {msg_type})")

    return {
        "marker": marker.hex(),
        "length": length,
        "type": msg_type,
        "type_name": "KEEPALIVE"
    }

def parse_bgp_message(data: bytes):
    if len(data) < 19:
        print("[!] Too short BGP message")
        return

    marker = data[:16]
    length, msg_type = struct.unpack("!HB", data[16:19])
    payload = data[19:length]

    if marker != b"\xff" * 16:
        print("[!] Invalid marker")
        return

    if msg_type == 1:  # OPEN
        msg = decode_open_message(data)
        print(
            f"{datetime.now()}[*] OPEN received: version={msg["version"]}, AS={msg["my_as"]}, hold_time={msg["hold_time"]}, router_id={msg["bgp_id"]}, opt_len={msg["opt_len"]}"
        )
        if msg["opt_len"] is not None and msg["opt_len"] > 0:
            opt_bytes = payload[10:10+msg["opt_len"]]
            print(f"{datetime.now()}[*] Optional Parameters:")
            parse_optional_params(opt_bytes)

    elif msg_type == 4:  # KEEPALIVE
        print(f"{datetime.now()}[*] KEEPALIVE received")
        

    elif msg_type == 2:  # UPDATE
        print(f"{datetime.now()}[*] UPDATE received (not parsed):", payload.hex())

    elif msg_type == 3:  # NOTIFICATION
        error_code, error_subcode = struct.unpack("!BB", payload[:2])
        print(f"{datetime.now()}[!] NOTIFICATION received: code={error_code}, subcode={error_subcode}")

    else:
        print(f"{datetime.now()}[?] Unknown BGP message type {msg_type}")

async def send_keepalives(writer):
    interval = HOLD_TIME // 3
    while True:
        await asyncio.sleep(interval)
        msg = build_keepalive_message()
        writer.write(msg)
        await writer.drain()
        print("{datetime.now()}[*] KEEPALIVE sent")


async def bgp_client():
    reader, writer = await asyncio.open_connection("127.0.0.1", BGP_PORT)
    print("{datetime.now()}[*] Connected to FRR BGP on port 179")

    # отправляем OPEN
    open_msg = build_open_message()
    writer.write(open_msg)
    await writer.drain()
    print("{datetime.now()}[*] OPEN message sent")

    # получаем первое сообщение
    data = await reader.read(4096)
    parse_bgp_message(data)

    # запускаем keepalive отправку
    asyncio.create_task(send_keepalives(writer))

    # основной цикл чтения
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                print("[!] Соединение закрыто")
                break
            parse_bgp_message(data)
    except KeyboardInterrupt:
        print("[*] Interrupted by user")
    reader, writer.close()
    await writer.wait_closed()
    print("[*] Connection closed")

        

# def main():
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#         s.connect(('127.0.0.1', BGP_PORT))
#         print("[*] Connected to FRR BGP on port 179")

#         open_msg = build_open_message()
#         s.sendall(open_msg)
#         print("[*] OPEN message sent")

#         # получаем ответ (OPEN или KEEPALIVE)
#         data = s.recv(1024)
#         print("[*] Received raw:", data.hex())

#         try:
#             decoded = decode_open_message(data)
#             print("[*] Decoded OPEN:", decoded)
#         except ValueError as e:
#             print("[*] Not an OPEN message:", e)
#         # пробуем декодировать как KEEPALIVE
#         data = s.recv(1024)
#         print("[*] Received raw:", data.hex())
#         try:
#             decoded = decode_keepalive_message(data)
#             print("[*] Decoded KEEPALIVE:", decoded)
#         except Exception as e:
#             print("[!] Ошибка при декодировании:", e)



if __name__ == "__main__":
    asyncio.run(bgp_client())
