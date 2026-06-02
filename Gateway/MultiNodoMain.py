import gc
import time
import ujson as json
import ubinascii

from AlLoRa.Nodes.Gateway import Gateway
from AlLoRa.Connectors.SX127x_connector import SX127x_connector

gc.enable()

CONFIG_FILE = "LoRa.json"
NODES_FILE = "Nodes.json"

# Evita reenviar dos veces el mismo fichero si el endpoint sigue apuntando al último recibido
LAST_EMITTED = {}


def emit_packet(source_mac, file_name, content_bytes):
    """
    Envía una sola línea JSON por USB serie.
    Mantiene el mismo formato que ya usa tu backend:
      - type = lora_rx
      - source_mac
      - file_name
      - size
      - encoding = hex
      - payload_hex
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


def should_emit(source_mac, file_name, size):
    """
    Devuelve True solo si ese fichero no se ha emitido ya para ese source.
    """
    key = source_mac
    current = (file_name, size)
    previous = LAST_EMITTED.get(key)

    if previous == current:
        return False

    LAST_EMITTED[key] = current
    return True


def process_endpoint(lora_gateway, endpoint):
    """
    Escucha a un endpoint concreto y, si recibe un fichero nuevo,
    lo emite por serie en formato compatible con el backend.
    """
    source_mac = endpoint.get_mac_address()

    # listening_time viene del Nodes.json de cada endpoint
    listening_time = getattr(endpoint, "listening_time", 20)

    lora_gateway.listen_to_endpoint(
        endpoint,
        listening_time,
        print_file=False,
        save_file=False
    )

    file = endpoint.get_current_file()
    if file is None:
        return

    try:
        file.file_writer.close()
    except Exception:
        pass

    content = file.get_content()
    if not content or len(content) == 0:
        return

    file_name = getattr(file, "name", "unknown.bin")
    size = len(content)

    if should_emit(source_mac, file_name, size):
        emit_packet(source_mac, file_name, content)


def main():
    connector = SX127x_connector()
    lora_gateway = Gateway(
        connector=connector,
        config_file=CONFIG_FILE,
        debug_hops=False,
        nodes_file=NODES_FILE
    )

    print('{"type":"gateway_status","status":"boot"}')
    print('{"type":"gateway_status","status":"ready","mode":"multi_source"}')

    if not lora_gateway.digital_endpoints:
        print(json.dumps({
            "type": "gateway_error",
            "error": "No hay endpoints activos en Nodes.json"
        }))

    while True:
        try:
            for ep in lora_gateway.digital_endpoints:
                try:
                    process_endpoint(lora_gateway, ep)
                except Exception as e:
                    print(json.dumps({
                        "type": "gateway_error",
                        "source_mac": ep.get_mac_address(),
                        "error": str(e)
                    }))

            gc.collect()
            time.sleep(1)

        except Exception as e:
            print(json.dumps({
                "type": "gateway_error",
                "error": str(e)
            }))
            gc.collect()
            time.sleep(2)


main()
