import time
import gc
import ujson as json
import uhashlib
import ucryptolib
from uos import urandom

from AlLoRa.Nodes.Source import Source
from AlLoRa.File import CTP_File
from AlLoRa.Connectors.SX127x_connector import SX127x_connector

from ecdsa_p256 import ecdsa_sign, public_key_uncompressed_from_priv
from ecdh_p256 import rand_scalar, ecdh_shared_secret

gc.enable()

# ====== Clave privada ECC de FIRMA (P-256) ======
PRIV_D = 1234

# ====== Clave pública ECDH del backend (uncompressed, 65 bytes, en hex) ======
# Aquí tienes que pegar la pública del backend, por ejemplo:
# BACKEND_ECDH_PUB_HEX = "04ab12...."
BACKEND_ECDH_PUB_HEX = "04341d0d3ddef4cdc8e6a49ec4550eee4a376ca2e10d6700ca16942ea8429a1c6a3c7ae08637125b97d31493bd749709c5ad0d4077d468c7283082b801a0ba5b1f"

# ====== Anti-replay ======
BOOT_ID = urandom(4).hex()
MSG_COUNTER = 0


def sha256(data: bytes) -> bytes:
    h = uhashlib.sha256()
    h.update(data)
    return h.digest()


def derive_device_id(priv_d: int) -> str:
    """
    device_id = SHA256(public_key_uncompressed_de_firma)
    """
    pub = public_key_uncompressed_from_priv(priv_d)
    return sha256(pub).hex()


DEVICE_ID = derive_device_id(PRIV_D)


def load_backend_ecdh_pub() -> bytes:
    if not BACKEND_ECDH_PUB_HEX:
        raise ValueError("Debes rellenar BACKEND_ECDH_PUB_HEX con la pública ECDH del backend")
    pub = bytes.fromhex(BACKEND_ECDH_PUB_HEX)
    if len(pub) != 65 or pub[0] != 0x04:
        raise ValueError("BACKEND_ECDH_PUB_HEX inválida")
    return pub


BACKEND_ECDH_PUB = load_backend_ecdh_pub()

# Clave ECDH efímera del Source para este boot
SOURCE_ECDH_PRIV = rand_scalar(urandom)
SOURCE_ECDH_PUB = public_key_uncompressed_from_priv(SOURCE_ECDH_PRIV)


def derive_session_key() -> bytes:
    shared_secret = ecdh_shared_secret(SOURCE_ECDH_PRIV, BACKEND_ECDH_PUB)
    return sha256(shared_secret)[:16]


SESSION_AES_KEY = derive_session_key()


def aes_ctr_crypt(key: bytes, nonce12: bytes, data: bytes) -> bytes:
    aes = ucryptolib.aes(key, 1)  # ECB
    out = bytearray(len(data))
    counter = 0

    for off in range(0, len(data), 16):
        block = data[off:off + 16]
        ctr_block = nonce12 + counter.to_bytes(4, "big")
        ks = aes.encrypt(ctr_block)

        for i in range(len(block)):
            out[off + i] = block[i] ^ ks[i]

        counter = (counter + 1) & 0xFFFFFFFF

    return bytes(out)


def canonical_unsigned_bytes(device_id: str, msg_type: int, timestamp: int,
                             counter: int, boot_id: str, ecdh_pub: str,
                             temp: float, hum: float) -> bytes:
    t = ("%.1f" % float(temp))
    h = ("%.1f" % float(hum))

    return (
        '{"device_id":"%s","msg_type":%d,"timestamp":%d,"counter":%d,'
        '"boot_id":"%s","ecdh_pub":"%s",'
        '"data":{"temperature":%s,"humidity":%s}}'
        % (device_id, int(msg_type), int(timestamp), int(counter), boot_id, ecdh_pub, t, h)
    ).encode()


def ecc_sign(message_bytes: bytes) -> bytes:
    return ecdsa_sign(message_bytes, PRIV_D)


def create_secure_payload():
    global MSG_COUNTER

    temp = 23.5
    hum = 48.1
    ts = int(time.time())
    ecdh_pub_hex = SOURCE_ECDH_PUB.hex()

    unsigned = canonical_unsigned_bytes(
        DEVICE_ID, 1, ts, MSG_COUNTER, BOOT_ID, ecdh_pub_hex, temp, hum
    )

    sig_hex = ecc_sign(unsigned).hex()

    msg = {
        "device_id": DEVICE_ID,
        "msg_type": 1,
        "timestamp": ts,
        "counter": MSG_COUNTER,
        "boot_id": BOOT_ID,
        "ecdh_pub": ecdh_pub_hex,
        "data": {
            "temperature": temp,
            "humidity": hum
        },
        "signature": sig_hex
    }

    plaintext = json.dumps(msg).encode()

    nonce = urandom(12)
    ciphertext = aes_ctr_crypt(SESSION_AES_KEY, nonce, plaintext)

    MSG_COUNTER += 1

    # Formato nuevo:
    #   ecdh_pub_source(65) || nonce(12) || ciphertext
    return SOURCE_ECDH_PUB + nonce + ciphertext


connector = SX127x_connector()
node = Source(connector, config_file="LoRa.json")
chunk_size = node.get_chunk_size()

print("Source listo. Esperando conexión...")
print("DEVICE_ID derivado:", DEVICE_ID)
print("SOURCE_ECDH_PUB:", SOURCE_ECDH_PUB.hex())

backup = node.establish_connection()
print("Conectado. Enviando payloads (ECDSA + ECDH + AES-CTR)...")

if backup:
    print("Hay backup pendiente")

file_counter = 0

while True:
    try:
        if not node.got_file():
            payload = create_secure_payload()

            if len(payload) > chunk_size:
                print("Payload demasiado grande para 1 chunk:", len(payload), ">", chunk_size)

            fname = "sec{:05d}.bin".format(file_counter)
            file_counter += 1

            node.set_file(CTP_File(
                name=fname,
                content=payload,
                chunk_size=chunk_size
            ))

            print("Nuevo payload seguro preparado:", fname, "bytes:", len(payload))

        node.send_file()
        gc.collect()
        time.sleep(3)

    except Exception as e:
        print("Error en Source:", e)
        gc.collect()
        time.sleep(2)
