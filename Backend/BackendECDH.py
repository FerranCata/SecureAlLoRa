import json
import time
import ssl
from pathlib import Path
from datetime import datetime
from threading import Lock
from typing import Optional, Tuple

import serial
from serial import SerialException
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


# ============================================================
# RUTAS Y CONFIGURACIÓN
# ============================================================
BASE_DIR = Path(__file__).resolve().parent
CERTS_DIR = "../mqtt_tls/certs"

MQTT_HOST = "localhost"
MQTT_PORT = 8883
MQTT_TOPIC_BASE = "tfg/lora"

# Ajusta estos nombres si en tu carpeta certs usas otros:
MQTT_CA = "../mqtt_tls/certs/ca.crt"
MQTT_CERT = "../mqtt_tls/certs/client.crt"      # certificado cliente del backend
MQTT_KEY = "../mqtt_tls/certs/client.key"       # clave cliente del backend

ADMIN_REQ_TOPIC = f"{MQTT_TOPIC_BASE}/admin/trusted_devices/request"
ADMIN_RESP_TOPIC = f"{MQTT_TOPIC_BASE}/admin/trusted_devices/response"

SERIAL_PORT = "/dev/ttyACM0"
BAUDRATE = 115200

TRUSTED_DEVICES_FILE = BASE_DIR / "trusted_devices.json"
BACKEND_ECDH_PRIV_FILE = BASE_DIR / "backend_ecdh_private.pem"

LOG_DIR = BASE_DIR / "logs" / "ECC"
LOG_DIR.mkdir(parents=True, exist_ok=True)

ECDH_PUB_LEN = 65
NONCE_LEN = 12

TRUSTED_LOCK = Lock()
COUNTER_LOCK = Lock()

TRUSTED_BY_DEVICE_ID = {}
TRUSTED_BY_SOURCE_MAC = {}

# anti-replay mejorado:
# guarda por device_id el boot_id y el último counter visto
LAST_SEEN = {}


# ============================================================
# UTILIDADES GENERALES
# ============================================================
def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def print_log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}")


# ============================================================
# GESTIÓN DE DISPOSITIVOS CONFIABLES
# ============================================================
def load_trusted_devices_raw() -> dict:
    if not TRUSTED_DEVICES_FILE.exists():
        return {"devices": []}

    with TRUSTED_DEVICES_FILE.open("r", encoding="utf-8") as f:
        raw = json.load(f)

    devices = raw.get("devices", [])
    if not isinstance(devices, list):
        raise ValueError("Formato inválido en trusted_devices.json: 'devices' debe ser una lista")

    return raw


def save_trusted_devices_raw(raw: dict) -> None:
    tmp_path = TRUSTED_DEVICES_FILE.with_suffix(".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(raw, f, indent=2, ensure_ascii=False)
    tmp_path.replace(TRUSTED_DEVICES_FILE)


def load_trusted_devices() -> Tuple[dict, dict]:
    raw = load_trusted_devices_raw()
    devices = raw.get("devices", [])

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

        by_device_id[str(device_id).strip().lower()] = dev
        by_source_mac[str(source_mac).strip().lower()] = dev

    return by_device_id, by_source_mac


def reload_trusted_devices() -> None:
    global TRUSTED_BY_DEVICE_ID, TRUSTED_BY_SOURCE_MAC
    with TRUSTED_LOCK:
        TRUSTED_BY_DEVICE_ID, TRUSTED_BY_SOURCE_MAC = load_trusted_devices()


def validate_admin_device_entry(data: dict) -> dict:
    required = ["device_id", "source_mac", "public_key_pem", "name", "active"]
    for key in required:
        if key not in data:
            raise ValueError(f"Falta campo obligatorio: {key}")

    device_id = str(data["device_id"]).strip().lower()
    source_mac = str(data["source_mac"]).strip().lower()
    public_key_pem = str(data["public_key_pem"])
    name = str(data["name"]).strip()
    active = bool(data["active"])

    if len(device_id) != 64:
        raise ValueError("device_id debe tener 64 caracteres hexadecimales")

    if len(source_mac) != 8:
        raise ValueError("source_mac debe tener 8 caracteres hexadecimales")

    int(device_id, 16)
    int(source_mac, 16)
    ECC.import_key(public_key_pem)

    if not name:
        raise ValueError("El nombre no puede estar vacío")

    return {
        "device_id": device_id,
        "source_mac": source_mac,
        "public_key_pem": public_key_pem,
        "name": name,
        "active": active,
    }


def add_or_update_trusted_device(entry: dict) -> str:
    with TRUSTED_LOCK:
        raw = load_trusted_devices_raw()
        devices = raw["devices"]

        idx = None
        for i, dev in enumerate(devices):
            dev_device_id = str(dev.get("device_id", "")).strip().lower()
            dev_source_mac = str(dev.get("source_mac", "")).strip().lower()

            if dev_device_id == entry["device_id"] or dev_source_mac == entry["source_mac"]:
                idx = i
                break

        if idx is None:
            devices.append(entry)
            action = "creado"
        else:
            devices[idx].update(entry)
            action = "actualizado"

        save_trusted_devices_raw(raw)

    reload_trusted_devices()
    return action


def set_device_active(device_id: str, active: bool) -> None:
    device_id = device_id.strip().lower()

    with TRUSTED_LOCK:
        raw = load_trusted_devices_raw()
        found = False

        for dev in raw["devices"]:
            if str(dev.get("device_id", "")).strip().lower() == device_id:
                dev["active"] = active
                found = True
                break

        if not found:
            raise ValueError("No se ha encontrado el dispositivo")

        save_trusted_devices_raw(raw)

    reload_trusted_devices()


def delete_trusted_device(device_id: str) -> None:
    device_id = device_id.strip().lower()

    with TRUSTED_LOCK:
        raw = load_trusted_devices_raw()
        original_len = len(raw["devices"])

        raw["devices"] = [
            dev for dev in raw["devices"]
            if str(dev.get("device_id", "")).strip().lower() != device_id
        ]

        if len(raw["devices"]) == original_len:
            raise ValueError("No se ha encontrado el dispositivo")

        save_trusted_devices_raw(raw)

    reload_trusted_devices()

    with COUNTER_LOCK:
        LAST_SEEN.pop(device_id, None)


def list_all_devices() -> list:
    raw = load_trusted_devices_raw()
    return raw["devices"]


# ============================================================
# ECDH BACKEND
# ============================================================
def load_or_create_backend_ecdh_private_key() -> Tuple[ECC.EccKey, bool]:
    if BACKEND_ECDH_PRIV_FILE.exists():
        key = ECC.import_key(BACKEND_ECDH_PRIV_FILE.read_text(encoding="utf-8"))
        return key, False

    key = ECC.generate(curve="P-256")
    BACKEND_ECDH_PRIV_FILE.write_text(
        key.export_key(format="PEM"),
        encoding="utf-8"
    )
    return key, True


def backend_ecdh_pub_hex(key: ECC.EccKey) -> str:
    pub = key.public_key()
    pub_uncompressed = (
        b"\x04"
        + int(pub.pointQ.x).to_bytes(32, "big")
        + int(pub.pointQ.y).to_bytes(32, "big")
    )
    return pub_uncompressed.hex()


BACKEND_ECDH_PRIV, BACKEND_ECDH_CREATED_NOW = load_or_create_backend_ecdh_private_key()


# ============================================================
# CRIPTOGRAFÍA
# ============================================================
def sha256_bytes(data: bytes) -> bytes:
    return SHA256.new(data).digest()


def aes_ctr_decrypt_library(key: bytes, nonce12: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce12)
    return cipher.decrypt(ciphertext)


def canonical_unsigned_bytes(
    device_id: str,
    msg_type: int,
    timestamp: int,
    counter: int,
    boot_id: str,
    ecdh_pub: str,
    temp: float,
    hum: float,
) -> bytes:
    t = ("%.1f" % float(temp))
    h = ("%.1f" % float(hum))

    return (
        '{"device_id":"%s","msg_type":%d,"timestamp":%d,"counter":%d,'
        '"boot_id":"%s","ecdh_pub":"%s",'
        '"data":{"temperature":%s,"humidity":%s}}'
        % (device_id, int(msg_type), int(timestamp), int(counter), boot_id, ecdh_pub, t, h)
    ).encode()


def get_public_key(device_id: str):
    with TRUSTED_LOCK:
        entry = TRUSTED_BY_DEVICE_ID.get(device_id)
    if not entry:
        raise ValueError(f"Dispositivo no autorizado: {device_id}")
    return ECC.import_key(entry["public_key_pem"])


def verify_signature(payload: dict) -> None:
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
        ecdh_pub=payload["ecdh_pub"],
        temp=data["temperature"],
        hum=data["humidity"],
    )

    signature = bytes.fromhex(sig_hex)
    pub_key = get_public_key(payload["device_id"])

    verifier = DSS.new(pub_key, "fips-186-3", encoding="binary")
    h = SHA256.new(unsigned)
    verifier.verify(h, signature)


def ecdh_shared_secret_backend(peer_pub_uncompressed: bytes) -> bytes:
    if len(peer_pub_uncompressed) != 65 or peer_pub_uncompressed[0] != 0x04:
        raise ValueError("Clave pública ECDH del Source inválida")

    x = int.from_bytes(peer_pub_uncompressed[1:33], "big")
    y = int.from_bytes(peer_pub_uncompressed[33:65], "big")

    peer_pub = ECC.construct(curve="P-256", point_x=x, point_y=y)
    shared_point = peer_pub.pointQ * int(BACKEND_ECDH_PRIV.d)
    shared_x = int(shared_point.x)

    return shared_x.to_bytes(32, "big")


def decrypt_and_parse_secure_payload(source_mac: str, payload_bytes: bytes) -> dict:
    min_len = ECDH_PUB_LEN + NONCE_LEN + 1
    if len(payload_bytes) < min_len:
        raise ValueError("Payload demasiado corto para ecdh_pub+nonce+ciphertext")

    source_mac = (source_mac or "").strip().lower()

    with TRUSTED_LOCK:
        entry = TRUSTED_BY_SOURCE_MAC.get(source_mac)

    if not entry:
        raise ValueError(f"source_mac no autorizado: {source_mac}")

    expected_device_id = entry["device_id"]

    ecdh_pub_wire = payload_bytes[:ECDH_PUB_LEN]
    nonce = payload_bytes[ECDH_PUB_LEN:ECDH_PUB_LEN + NONCE_LEN]
    ciphertext = payload_bytes[ECDH_PUB_LEN + NONCE_LEN:]

    shared_secret = ecdh_shared_secret_backend(ecdh_pub_wire)
    key = sha256_bytes(shared_secret)[:16]

    plaintext = aes_ctr_decrypt_library(key, nonce, ciphertext)

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except UnicodeDecodeError as e:
        raise ValueError("Descifrado inválido: clave ECDH/AES incorrecta o payload corrupto") from e
    except json.JSONDecodeError as e:
        raise ValueError("Descifrado inválido: el plaintext no es JSON válido") from e

    if payload.get("device_id") != expected_device_id:
        raise ValueError(
            f"device_id descifrado inesperado: {payload.get('device_id')} != {expected_device_id}"
        )

    ecdh_pub_json = payload.get("ecdh_pub")
    if not ecdh_pub_json:
        raise ValueError("Falta ecdh_pub dentro del payload")

    if ecdh_pub_json != ecdh_pub_wire.hex():
        raise ValueError("ecdh_pub no coincide entre cabecera binaria y JSON firmado")

    verify_signature(payload)
    return payload


# ============================================================
# PARSEO Y ANTI-REPLAY
# ============================================================
def parse_gateway_line(line: str) -> Optional[dict]:
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


def anti_replay_check(payload: dict) -> Tuple[bool, str]:
    device_id = payload.get("device_id")
    boot_id = payload.get("boot_id")
    counter = payload.get("counter")

    if device_id is None or boot_id is None or counter is None:
        return False, "faltan device_id/boot_id/counter"

    with COUNTER_LOCK:
        last = LAST_SEEN.get(device_id)

        if last is None:
            LAST_SEEN[device_id] = {"boot_id": boot_id, "counter": counter}
            return True, "ok_first_seen"

        last_boot_id = last["boot_id"]
        last_counter = last["counter"]

        # mismo boot -> el counter debe crecer
        if boot_id == last_boot_id:
            if counter <= last_counter:
                return False, f"replay_detected boot_id={boot_id} counter={counter} last={last_counter}"

            LAST_SEEN[device_id] = {"boot_id": boot_id, "counter": counter}
            return True, "ok_same_boot"

        # boot nuevo -> aceptamos y reiniciamos ventana
        LAST_SEEN[device_id] = {"boot_id": boot_id, "counter": counter}
        return True, f"ok_new_boot prev_boot={last_boot_id} new_boot={boot_id}"


def log_packet(obj: dict) -> None:
    dayfile = LOG_DIR / f"rx_{datetime.now().strftime('%Y%m%d')}.jsonl"
    with dayfile.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


# ============================================================
# SERIE
# ============================================================
def open_serial():
    ser = serial.Serial(
        SERIAL_PORT,
        BAUDRATE,
        timeout=1,
    )

    try:
        ser.dtr = True
    except Exception:
        pass

    time.sleep(1)
    return ser


# ============================================================
# MQTT: ADMIN + DATOS
# ============================================================
def publish_admin_response(client, request_id: str, ok: bool, data: Optional[dict] = None, error: Optional[str] = None):
    payload = {
        "request_id": request_id,
        "ok": ok,
        "data": data or {},
    }
    if error:
        payload["error"] = error

    client.publish(
        ADMIN_RESP_TOPIC,
        payload=json.dumps(payload, ensure_ascii=False),
        qos=1,
        retain=False,
    )


def handle_admin_request(client, data: dict):
    request_id = data.get("request_id")
    action = data.get("action")
    payload = data.get("payload", {})

    if not request_id:
        return

    try:
        if action == "get_backend_ecdh_pub":
            publish_admin_response(
                client,
                request_id,
                True,
                {
                    "backend_ecdh_pub_hex": backend_ecdh_pub_hex(BACKEND_ECDH_PRIV),
                    "created_now": BACKEND_ECDH_CREATED_NOW,
                },
            )
            return

        if action == "list_devices":
            publish_admin_response(
                client,
                request_id,
                True,
                {"devices": list_all_devices()},
            )
            return

        if action == "add_or_update_device":
            entry = validate_admin_device_entry(payload)
            action_done = add_or_update_trusted_device(entry)

            publish_admin_response(
                client,
                request_id,
                True,
                {
                    "action": action_done,
                    "device_id": entry["device_id"],
                    "backend_ecdh_pub_hex": backend_ecdh_pub_hex(BACKEND_ECDH_PRIV),
                },
            )
            return

        if action == "deactivate_device":
            device_id = str(payload["device_id"]).strip().lower()
            set_device_active(device_id, False)
            publish_admin_response(client, request_id, True, {"device_id": device_id})
            return

        if action == "activate_device":
            device_id = str(payload["device_id"]).strip().lower()
            set_device_active(device_id, True)
            publish_admin_response(client, request_id, True, {"device_id": device_id})
            return

        if action == "delete_device":
            device_id = str(payload["device_id"]).strip().lower()
            delete_trusted_device(device_id)
            publish_admin_response(client, request_id, True, {"device_id": device_id})
            return

        publish_admin_response(
            client,
            request_id,
            False,
            error=f"Acción no soportada: {action}",
        )

    except Exception as e:
        publish_admin_response(client, request_id, False, error=str(e))


def on_mqtt_connect(client, userdata, flags, rc):
    print_log(f"MQTT TLS conectado con rc={rc}")
    client.subscribe(ADMIN_REQ_TOPIC, qos=1)


def on_mqtt_message(client, userdata, msg):
    try:
        if msg.topic != ADMIN_REQ_TOPIC:
            return

        data = json.loads(msg.payload.decode("utf-8"))
        handle_admin_request(client, data)

    except Exception as e:
        print_log(f"Error procesando mensaje admin MQTT: {e}")


def make_mqtt_client():
    client = mqtt.Client(client_id="backend-lora", protocol=mqtt.MQTTv311)

    client.tls_set(
        ca_certs=str(MQTT_CA),
        certfile=str(MQTT_CERT),
        keyfile=str(MQTT_KEY),
        cert_reqs=ssl.CERT_REQUIRED,
        tls_version=ssl.PROTOCOL_TLS_CLIENT,
    )

    client.on_connect = on_mqtt_connect
    client.on_message = on_mqtt_message

    client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
    client.loop_start()
    return client


def publish_payload_mqtt(client, payload: dict):
    device_id = payload.get("device_id", "unknown")
    topic = f"{MQTT_TOPIC_BASE}/{device_id}/data"
    client.publish(topic, json.dumps(payload, ensure_ascii=False), qos=1)


# ============================================================
# MAIN
# ============================================================
def main():
    reload_trusted_devices()

    mqtt_client = make_mqtt_client()
    print_log(f"MQTT TLS listo en {MQTT_HOST}:{MQTT_PORT}")
    print_log(f"Topic admin request: {ADMIN_REQ_TOPIC}")
    print_log(f"Topic admin response: {ADMIN_RESP_TOPIC}")

    if BACKEND_ECDH_CREATED_NOW:
        print_log("Se ha creado backend_ecdh_private.pem por primera vez")
    else:
        print_log("Se reutiliza backend_ecdh_private.pem existente")

    print_log(f"BACKEND_ECDH_PUB_HEX = {backend_ecdh_pub_hex(BACKEND_ECDH_PRIV)}")

    while True:
        try:
            ser = open_serial()
            print_log(f"Puerto serie abierto: {SERIAL_PORT} @ {BAUDRATE}")

            while True:
                raw = ser.readline()
                if not raw:
                    continue

                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                try:
                    obj = parse_gateway_line(line)
                    if obj is None:
                        continue

                    payload = obj["payload"]

                    anti_ok, anti_reason = anti_replay_check(payload)
                    obj["anti_replay_ok"] = anti_ok
                    obj["anti_replay_reason"] = anti_reason
                    obj["crypto_ok"] = True
                    obj["ecc_ok"] = True

                    log_packet(obj)

                    if anti_ok:
                        publish_payload_mqtt(mqtt_client, payload)
                        print(json.dumps(payload, ensure_ascii=False))
                    else:
                        print_log(f"DESCARTADO replay: {anti_reason}")

                except Exception as e:
                    print_log(f"DESCARTADO: {e}")

        except SerialException as e:
            print_log(f"Error serie: {e}")
            time.sleep(2)

        except KeyboardInterrupt:
            print_log("Salida por teclado")
            break

        except Exception as e:
            print_log(f"Error general: {e}")
            time.sleep(2)


if __name__ == "__main__":
    main()
