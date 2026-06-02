import json
import time
from pathlib import Path
from datetime import datetime

import serial
from serial import SerialException
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

SERIAL_PORT = "/dev/ttyACM0"
BAUDRATE = 115200

LOG_DIR = Path("logs/AES")
LOG_DIR.mkdir(exist_ok=True)

LAST_COUNTER = {}

# source_mac -> device_id
DEVICE_HINT_BY_SOURCE_MAC = {
    "4a300708": "Source",
}

def now_iso():
    return datetime.now().isoformat(timespec="seconds")

def sha256_bytes(data: bytes) -> bytes:
    return SHA256.new(data).digest()

def derive_aes_key(device_id: str) -> bytes:
    # Debe ser EXACTAMENTE igual que en el Source
    return sha256_bytes(device_id.encode())[:16]

def aes_ctr_crypt(key: bytes, nonce12: bytes, data: bytes) -> bytes:
    """
    CTR: keystream = AES_ECB(nonce12 || counter32_be)
    ciphertext = plaintext XOR keystream
    """
    aes = AES.new(key, AES.MODE_ECB)
    out = bytearray(len(data))
    counter = 0

    for off in range(0, len(data), 16):
        block = data[off:off+16]
        ctr_block = nonce12 + counter.to_bytes(4, "big")
        ks = aes.encrypt(ctr_block)

        for i in range(len(block)):
            out[off + i] = block[i] ^ ks[i]

        counter = (counter + 1) & 0xFFFFFFFF

    return bytes(out)

def decrypt_and_parse_secure_payload(source_mac: str, payload_bytes: bytes):
    if len(payload_bytes) < 13:
        raise ValueError("Payload demasiado corto para nonce+ciphertext")

    device_id_hint = DEVICE_HINT_BY_SOURCE_MAC.get(source_mac)
    if not device_id_hint:
        raise ValueError(f"No hay device_id asociado a source_mac={source_mac}")

    nonce = payload_bytes[:12]
    ciphertext = payload_bytes[12:]

    key = derive_aes_key(device_id_hint)
    plaintext = aes_ctr_crypt(key, nonce, ciphertext)

    payload = json.loads(plaintext.decode())

    if payload.get("device_id") != device_id_hint:
        raise ValueError(
            f"device_id descifrado inesperado: {payload.get('device_id')} != {device_id_hint}"
        )

    return payload

def parse_gateway_line(line: str):
    """
    Devuelve:
      - None si la línea no es JSON útil
      - obj con payload descifrado si es un paquete LoRa válido
    """
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        # Ignora ruido del gateway / logs de AlLoRa
        return None

    if obj.get("type") != "lora_rx":
        # Ignora mensajes de estado del gateway
        return None

    if obj.get("encoding") != "hex":
        raise ValueError("Encoding no soportado")

    payload_bytes = bytes.fromhex(obj["payload_hex"])
    payload = decrypt_and_parse_secure_payload(obj.get("source_mac"), payload_bytes)

    obj["payload"] = payload
    return obj

def anti_replay_check(payload: dict):
    device_id = payload.get("device_id")
    counter = payload.get("counter")

    if device_id is None or counter is None:
        return False, "faltan device_id/counter"

    last = LAST_COUNTER.get(device_id)

    if last is not None and counter <= last:
        return False, f"replay_detected counter={counter} last={last}"

    LAST_COUNTER[device_id] = counter
    return True, "ok"

def log_packet(obj: dict):
    dayfile = LOG_DIR / f"rx_{datetime.now().strftime('%Y%m%d')}.jsonl"
    with dayfile.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def open_serial():
    ser = serial.Serial(SERIAL_PORT, BAUDRATE, timeout=1, exclusive=True)

    # Importante en tu caso: dejar DTR activo
    try:
        ser.dtr = True
    except Exception:
        pass

    time.sleep(1)
    return ser

def main():
    print(f"[{now_iso()}] Backend escuchando en {SERIAL_PORT}")

    while True:
        ser = None
        try:
            ser = open_serial()
            print(f"[{now_iso()}] Puerto abierto")

            while True:
                try:
                    raw = ser.readline()
                except SerialException as e:
                    print(f"[{now_iso()}] Puerto perdido: {e}")
                    break

                if not raw:
                    continue

                line = raw.decode(errors="replace").strip()
                if not line:
                    continue

                try:
                    obj = parse_gateway_line(line)
                except Exception:
                    # Ignora líneas corruptas o ruido no descifrable
                    continue

                if obj is None:
                    continue

                payload = obj["payload"]
                ok, reason = anti_replay_check(payload)

                result = {
                    "ts_host": now_iso(),
                    "gateway_source_mac": obj.get("source_mac"),
                    "file_name": obj.get("file_name"),
                    "size": obj.get("size"),
                    "crypto_ok": True,
                    "anti_replay_ok": ok,
                    "anti_replay_reason": reason,
                    "payload": payload
                }

                log_packet(result)

                # Muestra solo el JSON descifrado
                print(json.dumps(payload, ensure_ascii=False))

        except SerialException as e:
            print(f"[{now_iso()}] No se pudo abrir el puerto: {e}")

        finally:
            if ser is not None:
                try:
                    ser.close()
                except Exception:
                    pass

        time.sleep(2)

if __name__ == "__main__":
    main()
