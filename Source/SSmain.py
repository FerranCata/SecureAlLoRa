import time
import gc
import ujson as json

from AlLoRa.Nodes.Source import Source
from AlLoRa.File import CTP_File
from AlLoRa.Connectors.SX127x_connector import SX127x_connector

gc.enable()

# ====== Identidad del nodo ======
DEVICE_ID = "Source"

MSG_COUNTER = 0

def create_plain_payload():
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

    MSG_COUNTER += 1
    return json.dumps(msg).encode()

# ====== AlLoRa Source ======
connector = SX127x_connector()
node = Source(connector, config_file="LoRa.json")
chunk_size = node.get_chunk_size()

print("Source listo. Esperando conexión...")
backup = node.establish_connection()
print("Conectado. Enviando payloads sin seguridad...")

if backup:
    print("Hay backup pendiente")

file_counter = 0

while True:
    try:
        if not node.got_file():
            payload = create_plain_payload()

            if len(payload) > chunk_size:
                print("Payload demasiado grande para 1 chunk:", len(payload), ">", chunk_size)

            fname = "payload{:05d}.json".format(file_counter)
            file_counter += 1

            node.set_file(CTP_File(
                name=fname,
                content=payload,
                chunk_size=chunk_size
            ))

            print("Nuevo payload preparado:", fname, "bytes:", len(payload))
            print(payload.decode())

        node.send_file()
        gc.collect()
        time.sleep(3)

    except Exception as e:
        print("Error en Source:", e)
        gc.collect()
        time.sleep(2)
