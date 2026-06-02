import time
import gc
import ujson as json
import uhashlib
import ucryptolib
from uos import urandom

from AlLoRa.Nodes.Source import Source
from AlLoRa.File import CTP_File
from AlLoRa.Connectors.SX127x_connector import SX127x_connector

gc.enable()

# ====== Identidad del nodo ======
DEVICE_ID = "Source"
MSG_COUNTER = 0

def sha256(data: bytes) -> bytes:
    h = uhashlib.sha256()
    h.update(data)
    return h.digest()

def derive_aes_key(device_id: str) -> bytes:
    # AES-128 a partir de SHA-256(device_id)
    return sha256(device_id.encode())[:16]

def aes_ctr_crypt(key: bytes, nonce12: bytes, data: bytes) -> bytes:
    """
    CTR: keystream = AES_ECB(nonce12 || counter32_be)
    ciphertext = plaintext XOR keystream
    """
    aes = ucryptolib.aes(key, 1)  # 1 = ECB
    out = bytearray(len(data))
    counter = 0

    for off in range(0, len(data), 16):
        block = data[off:off+16]
        ctr_block = nonce12 + counter.to_bytes(4, "big")  # 16 bytes total
        ks = aes.encrypt(ctr_block)

        for i in range(len(block)):
            out[off + i] = block[i] ^ ks[i]

        counter = (counter + 1) & 0xFFFFFFFF

    return bytes(out)

def create_secure_payload():
    global MSG_COUNTER

    msg = {
        "device_id": DEVICE_ID,
        "msg_type": 1,
        "timestamp": int(time.time()),
        "counter": MSG_COUNTER,
        "data": {
            "temperature": 23.5,
            "humidity": 48.1
        }
    }

    plaintext = json.dumps(msg).encode()

    nonce = urandom(12)
    key = derive_aes_key(DEVICE_ID)
    ciphertext = aes_ctr_crypt(key, nonce, plaintext)

    MSG_COUNTER += 1

    # Formato final: nonce || ciphertext
    return nonce + ciphertext

# ====== AlLoRa Source ======
connector = SX127x_connector()
node = Source(connector, config_file="LoRa.json")
chunk_size = node.get_chunk_size()

print("Source listo. Esperando conexión...")
backup = node.establish_connection()
print("Conectado. Enviando payloads con AES-CTR...")

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

            print("Nuevo payload AES preparado:", fname, "bytes:", len(payload))

        node.send_file()
        gc.collect()
        time.sleep(3)

    except Exception as e:
        print("Error en Source:", e)
        gc.collect()
        time.sleep(2)
