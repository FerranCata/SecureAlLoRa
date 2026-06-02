import json
import time
from pathlib import Path
from datetime import datetime
import serial

SERIAL_PORT = "/dev/ttyACM0"   # cambia si tu gateway sale en otro puerto
BAUDRATE = 115200

LOG_DIR = Path("logs/SS")
LOG_DIR.mkdir(exist_ok=True)

LAST_COUNTER = {}   # anti-replay por device_id


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def parse_gateway_line(line: str):
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    if obj.get("type") != "lora_rx":
        return obj

    if obj.get("encoding") != "hex":
        raise ValueError("Encoding no soportado")

    payload_bytes = bytes.fromhex(obj["payload_hex"])

    try:
        payload = json.loads(payload_bytes.decode())
    except Exception as e:
        raise ValueError(f"Payload JSON inválido: {e}") from e

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


def main():
    print(f"[{now_iso()}] Abriendo puerto {SERIAL_PORT} a {BAUDRATE} bps")

    with serial.Serial(SERIAL_PORT, BAUDRATE, timeout=1) as ser:
        while True:
            raw = ser.readline()
            if not raw:
                continue

            line = raw.decode(errors="replace").strip()
            if not line:
                continue

            try:
                obj = parse_gateway_line(line)
            except Exception as e:
                print(f"[{now_iso()}] ERROR parseando línea: {e}")
                print("  >", line)
                continue

            # Mensajes de estado del gateway
            if obj is None:
                continue

            if obj.get("type") != "lora_rx":
                print(f"[{now_iso()}] GATEWAY:", obj)
                continue

            payload = obj["payload"]
            ok, reason = anti_replay_check(payload)

            result = {
                "ts_host": now_iso(),
                "gateway_source_mac": obj.get("source_mac"),
                "file_name": obj.get("file_name"),
                "size": obj.get("size"),
                "anti_replay_ok": ok,
                "anti_replay_reason": reason,
                "payload": payload
            }

            log_packet(result)

            data = payload.get("data", {})
            print(
                f"[{result['ts_host']}] RX "
                f"device_id={payload.get('device_id')} "
                f"counter={payload.get('counter')} "
                f"temp={data.get('temperature')} "
                f"hum={data.get('humidity')} "
                f"anti_replay={reason}"
            )


if __name__ == "__main__":
    main()
