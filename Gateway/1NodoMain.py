import gc
import time
import ujson as json
import ubinascii

from AlLoRa.Nodes.Requester import Requester
from AlLoRa.Connectors.SX127x_connector import SX127x_connector
from AlLoRa.Digital_Endpoint import Digital_Endpoint

gc.enable()

SOURCE_MAC = "4a300708"   # cambia esto si cambia tu Source

def emit_packet(source_mac, file_name, content_bytes):
    """
    Envía una sola línea JSON por USB serie.
    El payload va en hex para que también sirva cuando luego sea binario (AES/ECC).
    """
    line = {
        "type": "lora_rx",
        "source_mac": source_mac,
        "file_name": file_name,
        "size": len(content_bytes),
        "encoding": "hex",
        "payload_hex": ubinascii.hexlify(content_bytes).decode()
    }
    print(json.dumps(line))

connector = SX127x_connector()
lora_node = Requester(connector, config_file="LoRa.json")

node_a = Digital_Endpoint(
    name="T",
    mac_address=SOURCE_MAC,
    active=True
)

print('{"type":"gateway_status","status":"boot"}')
print('{"type":"gateway_status","status":"ready","source_mac":"%s"}' % SOURCE_MAC)

while True:
    try:
        lora_node.listen_to_endpoint(
            node_a,
            100,
            print_file=False,
            save_file=False,
            one_file=True
        )

        file = node_a.get_current_file()

        if file is not None:
            try:
                file.file_writer.close()
            except Exception:
                pass

            content = file.get_content()

            if content and len(content) > 0:
                emit_packet(
                    SOURCE_MAC,
                    getattr(file, "name", "unknown.bin"),
                    content
                )
            else:
                print('{"type":"gateway_status","status":"empty_file"}')
        else:
            print('{"type":"gateway_status","status":"no_file"}')

    except Exception as e:
        print(json.dumps({
            "type": "gateway_error",
            "error": str(e)
        }))

    gc.collect()
    time.sleep(2)
