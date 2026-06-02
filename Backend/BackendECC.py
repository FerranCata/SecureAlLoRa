import json
import time
from pathlib import Path
from datetime import datetime

import serial
from serial import SerialException
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

SERIAL_PORT = "/dev/ttyACM0"
BAUDRATE = 115200
TRUSTED_DEVICES_FILE = Path("trusted_devices.json")

LOG_DIR = Path("logs/ECC")
LOG_DIR.mkdir(exist_ok=True)

LAST_COUNTER = {}


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def load_trusted_devices():
    if not TRUSTED_DEVICES_FILE.exists():
        raise FileNotFoundError(f"No existe {TRUSTED_DEVICES_FILE}")

    with TRUSTED_DEVICES_FILE.open("r", encoding="utf-8") as f:
        raw = json.load(f)

    devices = raw.get("devices", [])
    if not isinstance(devices, list):
        raise ValueError("Formato inválido en trusted_devices.json: 'devices' debe ser una lista")

    by_device_id = {}
    by_source_mac = {}

    for dev in devices:
        if not dev.get("active", True):
            continue

        device_id = dev.get("device_id")
        source_mac = dev.get("source_mac")
        public_key_pem = dev.get("public_key_pem")

        if not device_id or not source_mac or not public_key_pem:
            raise ValueError("Cada dispositivo debe incluir device_id, source_mac y public_key_pem")

        by_device_id[device_id] = dev
        by_source_mac[source_mac] = dev

    return by_device_id, by_source_mac


TRUSTED_BY_DEVICE_ID, TRUSTED_BY_SOURCE_MAC = load_trusted_devices()


def sha256_bytes(data: bytes) -> bytes:
    return SHA256.new(data).digest()


def derive_aes_key(device_id: str) -> bytes:
    # Debe ser EXACTAMENTE igual que en el Source
    return sha256_bytes(device_id.encode())[:16]


def aes_ctr_decrypt_lib(key: bytes, nonce12: bytes, ciphertext: bytes) -> bytes:
    """
    Descifrado AES-CTR usando la librería estándar PyCryptodome.
    Debe reproducir el mismo esquema del Source:
    - nonce de 12 bytes
    - contador inicial = 0
    """
    if len(nonce12) != 12:
        raise ValueError(f"Nonce inválido: se esperaban 12 bytes y llegaron {len(nonce12)}")

    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce12, initial_value=0)
    return cipher.decrypt(ciphertext)


def canonical_unsigned_bytes(device_id: str, msg_type: int, timestamp: int,
                             counter: int, boot_id: str, temp: float, hum: float) -> bytes:
    """
    Debe ser EXACTAMENTE igual al Source.
    """
    t = ("%.1f" % float(temp))
    h = ("%.1f" % float(hum))

    return (
        '{"device_id":"%s","msg_type":%d,"timestamp":%d,"counter":%d,"boot_id":"%s",'
        '"data":{"temperature":%s,"humidity":%s}}'
        % (device_id, int(msg_type), int(timestamp), int(counter), boot_id, t, h)
    ).encode()


def get_public_key(device_id: str):
    entry = TRUSTED_BY_DEVICE_ID.get(device_id)
    if not entry:
        raise ValueError(f"Dispositivo no autorizado: {device_id}")

    return ECC.import_key(entry["public_key_pem"])


def verify_signature(payload: dict):
    sig_hex = payload.get("signature")
    if not sig_hex:
        raise ValueError("Falta signature")

    data = payload.get("data", {})
    unsigned = canonical_unsigned_bytes(
        device_id=payload["device_id"],
        msg_type=payload["msg_type"],
        timestamp=payload["timestamp"],
        counter=payload["counter"],
        boot_id=payload["boot_id"],
        temp=data["temperature"],
        hum=data["humidity"],
    )

    signature = bytes.fromhex(sig_hex)
    pub_key = get_public_key(payload["device_id"])

    # La firma viene como r||s (64 bytes)
    verifier = DSS.new(pub_key, "fips-186-3", encoding="binary")
    h = SHA256.new(unsigned)
    verifier.verify(h, signature)


def decrypt_and_parse_secure_payload(source_mac: str, payload_bytes: bytes):
    if len(payload_bytes) < 13:
        raise ValueError("Payload demasiado corto para nonce+ciphertext")

    entry = TRUSTED_BY_SOURCE_MAC.get(source_mac)
    if not entry:
        raise ValueError(f"source_mac no autorizado: {source_mac}")

    device_id_hint = entry["device_id"]

    nonce = payload_bytes[:12]
    ciphertext = payload_bytes[12:]

    key = derive_aes_key(device_id_hint)
    plaintext = aes_ctr_decrypt_lib(key, nonce, ciphertext)

    payload = json.loads(plaintext.decode("utf-8"))

    if payload.get("device_id") != device_id_hint:
        raise ValueError(
            f"device_id descifrado inesperado: {payload.get('device_id')} != {device_id_hint}"
        )

    verify_signature(payload)
    return payload


def parse_gateway_line(line: str):
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    if obj.get("type") != "lora_rx":
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

    try:
        ser.dtr = True
    except Exception:
        pass

    time.sleep(1)
    return ser


def main():
    print(f"[{now_iso()}] Backend escuchando en {SERIAL_PORT}")
    print(f"[{now_iso()}] Dispositivos autorizados: {list(TRUSTED_BY_DEVICE_ID.keys())}")

    while True:
        ser = None
        try:
            ser = open_serial()
            print(f"[{now_iso()}] Puerto abierto")

            while True:
                try:
                    raw = ser.readline()
                except SerialException:
                    break

                if not raw:
                    continue

                line = raw.decode(errors="replace").strip()
                if not line:
                    continue

                try:
                    obj = parse_gateway_line(line)
                except Exception as e:
                    print(f"[{now_iso()}] DESCARTADO: {e}")
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
                    "ecc_ok": True,
                    "anti_replay_ok": ok,
                    "anti_replay_reason": reason,
                    "payload": payload
                }

                log_packet(result)

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
