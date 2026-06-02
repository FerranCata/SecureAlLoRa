import json
import ssl
import uuid
import time
import queue
import hashlib
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import paho.mqtt.client as mqtt
from Crypto.PublicKey import ECC

# =========================
# MQTT TLS CONFIG (ADMIN)
# =========================
MQTT_HOST = "localhost"
MQTT_PORT = 8883

MQTT_CA = "../mqtt_tls/certs/ca.crt"
MQTT_CERT = "../mqtt_tls/certs/admin_client.crt"
MQTT_KEY = "../mqtt_tls/certs/admin_client.key"

ADMIN_REQ_TOPIC = "tfg/lora/admin/trusted_devices/request"
ADMIN_RESP_TOPIC = "tfg/lora/admin/trusted_devices/response"


def normalize_mac(mac: str) -> str:
    mac = mac.strip().lower().replace(":", "").replace("-", "").replace(" ", "")
    if len(mac) != 8:
        raise ValueError("La MAC debe tener 8 caracteres hexadecimales, por ejemplo: 4a300708")
    int(mac, 16)
    return mac


def priv_to_signing_key(priv_d: int) -> ECC.EccKey:
    return ECC.construct(curve="P-256", d=priv_d)


def public_key_pem_from_priv(priv_d: int) -> str:
    key = priv_to_signing_key(priv_d)
    return key.public_key().export_key(format="PEM")


def public_key_uncompressed_from_priv(priv_d: int) -> bytes:
    key = priv_to_signing_key(priv_d)
    pub = key.public_key()
    return (
        b"\x04"
        + int(pub.pointQ.x).to_bytes(32, "big")
        + int(pub.pointQ.y).to_bytes(32, "big")
    )


def derive_device_id(priv_d: int) -> str:
    pub_uncompressed = public_key_uncompressed_from_priv(priv_d)
    return hashlib.sha256(pub_uncompressed).hexdigest()


class MqttRpcClient:
    def __init__(self):
        self._pending = {}
        self._lock = threading.Lock()
        self._connected = threading.Event()

        self.client = mqtt.Client(client_id=f"trusted-admin-gui-{uuid.uuid4().hex[:8]}")
        self.client.tls_set(
            ca_certs=MQTT_CA,
            certfile=MQTT_CERT,
            keyfile=MQTT_KEY,
            cert_reqs=ssl.CERT_REQUIRED,
            tls_version=ssl.PROTOCOL_TLS_CLIENT,
        )
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect

    def connect(self):
        self.client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
        self.client.loop_start()
        if not self._connected.wait(timeout=5):
            raise RuntimeError("No se pudo conectar al broker MQTT TLS")

    def close(self):
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            pass

    def _on_connect(self, client, userdata, flags, rc):
        if rc != 0:
            return
        client.subscribe(ADMIN_RESP_TOPIC, qos=1)
        self._connected.set()

    def _on_disconnect(self, client, userdata, rc):
        self._connected.clear()

    def _on_message(self, client, userdata, msg):
        try:
            data = json.loads(msg.payload.decode("utf-8"))
            request_id = data.get("request_id")
            if not request_id:
                return

            with self._lock:
                pending = self._pending.get(request_id)

            if pending is not None:
                pending["response"] = data
                pending["event"].set()

        except Exception:
            pass

    def request(self, action: str, payload: dict | None = None, timeout: float = 5.0) -> dict:
        if payload is None:
            payload = {}

        request_id = uuid.uuid4().hex
        event = threading.Event()

        with self._lock:
            self._pending[request_id] = {"event": event, "response": None}

        message = {
            "request_id": request_id,
            "action": action,
            "payload": payload,
            "ts": time.time(),
        }

        info = self.client.publish(
            ADMIN_REQ_TOPIC,
            payload=json.dumps(message, ensure_ascii=False),
            qos=1,
            retain=False,
        )
        info.wait_for_publish()

        ok = event.wait(timeout=timeout)

        with self._lock:
            pending = self._pending.pop(request_id, None)

        if not ok or pending is None or pending["response"] is None:
            raise TimeoutError(f"No hubo respuesta MQTT para la acción '{action}'")

        response = pending["response"]
        if not response.get("ok", False):
            raise RuntimeError(response.get("error", "Error desconocido en backend"))

        return response


class TrustedDevicesAdminGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Gestión segura de dispositivos confiables")
        self.root.geometry("1280x820")

        self.rpc = MqttRpcClient()
        self.devices_by_id = {}
        self.current_backend_pub_hex = ""

        self.name_var = tk.StringVar()
        self.mac_var = tk.StringVar()
        self.priv_var = tk.StringVar()
        self.active_var = tk.BooleanVar(value=True)

        self._build_ui()

        try:
            self.rpc.connect()
            self.load_backend_ecdh()
            self.refresh_devices()
        except Exception as e:
            messagebox.showerror("Error MQTT", str(e))

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)

        ttk.Label(
            main,
            text="Gestión segura de dispositivos confiables por MQTT TLS",
            font=("Arial", 16, "bold")
        ).pack(anchor="w", pady=(0, 10))

        top = ttk.PanedWindow(main, orient="horizontal")
        top.pack(fill="both", expand=True)

        left = ttk.Frame(top, padding=6)
        right = ttk.Frame(top, padding=6)
        top.add(left, weight=2)
        top.add(right, weight=3)

        # Formulario
        form = ttk.LabelFrame(left, text="Alta / actualización", padding=10)
        form.pack(fill="x", pady=(0, 10))

        ttk.Label(form, text="Nombre").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(form, textvariable=self.name_var, width=42).grid(row=0, column=1, sticky="ew", pady=6)

        ttk.Label(form, text="MAC (8 hex)").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(form, textvariable=self.mac_var, width=42).grid(row=1, column=1, sticky="ew", pady=6)

        ttk.Label(form, text="Clave privada ECC (entero)").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(form, textvariable=self.priv_var, width=42).grid(row=2, column=1, sticky="ew", pady=6)

        ttk.Checkbutton(form, text="Dispositivo activo", variable=self.active_var).grid(
            row=3, column=1, sticky="w", pady=6
        )

        form.columnconfigure(1, weight=1)

        btns_form = ttk.Frame(form)
        btns_form.grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 0))

        ttk.Button(btns_form, text="Dar de alta / actualizar", command=self.on_register).pack(side="left")
        ttk.Button(btns_form, text="Limpiar formulario", command=self.clear_form).pack(side="left", padx=8)

        # ECDH
        ecdh_box = ttk.LabelFrame(left, text="Clave pública ECDH del backend", padding=10)
        ecdh_box.pack(fill="both", expand=False, pady=(0, 10))

        self.ecdh_text = tk.Text(ecdh_box, height=8, wrap="word")
        self.ecdh_text.pack(fill="both", expand=True)

        btns_ecdh = ttk.Frame(ecdh_box)
        btns_ecdh.pack(fill="x", pady=(8, 0))
        ttk.Button(btns_ecdh, text="Consultar BACKEND_ECDH_PUB_HEX", command=self.load_backend_ecdh).pack(side="left")
        ttk.Button(btns_ecdh, text="Copiar", command=self.copy_backend_pub).pack(side="left", padx=8)

        # Resultado
        result_box = ttk.LabelFrame(left, text="Resultado", padding=10)
        result_box.pack(fill="both", expand=True)

        self.result_text = tk.Text(result_box, wrap="word")
        self.result_text.pack(fill="both", expand=True)

        # Tabla
        table_box = ttk.LabelFrame(right, text="Dispositivos dados de alta", padding=10)
        table_box.pack(fill="both", expand=True, pady=(0, 10))

        columns = ("name", "source_mac", "active", "device_id_short")
        self.tree = ttk.Treeview(table_box, columns=columns, show="headings", height=14)
        self.tree.heading("name", text="Nombre")
        self.tree.heading("source_mac", text="MAC")
        self.tree.heading("active", text="Activo")
        self.tree.heading("device_id_short", text="device_id")
        self.tree.column("name", width=220)
        self.tree.column("source_mac", width=90, anchor="center")
        self.tree.column("active", width=70, anchor="center")
        self.tree.column("device_id_short", width=260)

        scrollbar = ttk.Scrollbar(table_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select_device)

        btns_table = ttk.Frame(right)
        btns_table.pack(fill="x", pady=(0, 10))

        ttk.Button(btns_table, text="Recargar lista", command=self.refresh_devices).pack(side="left")
        ttk.Button(btns_table, text="Ver detalle", command=self.show_selected_device).pack(side="left", padx=8)
        ttk.Button(btns_table, text="Dar de baja", command=self.deactivate_selected_device).pack(side="left", padx=8)
        ttk.Button(btns_table, text="Reactivar", command=self.activate_selected_device).pack(side="left", padx=8)

        tk.Button(
            btns_table,
            text="Eliminar",
            command=self.delete_selected_device,
            bg="#c62828",
            fg="white",
            activebackground="#b71c1c",
            activeforeground="white",
            relief="raised",
            padx=10
        ).pack(side="left", padx=8)

        detail_box = ttk.LabelFrame(right, text="Información del dispositivo seleccionado", padding=10)
        detail_box.pack(fill="both", expand=True)

        self.detail_text = tk.Text(detail_box, wrap="word")
        self.detail_text.pack(fill="both", expand=True)

    def _set_text(self, widget: tk.Text, value: str):
        widget.delete("1.0", "end")
        widget.insert("1.0", value)

    def clear_form(self):
        self.name_var.set("")
        self.mac_var.set("")
        self.priv_var.set("")
        self.active_var.set(True)

    def load_backend_ecdh(self):
        try:
            response = self.rpc.request("get_backend_ecdh_pub", {})
            pub_hex = response["data"]["backend_ecdh_pub_hex"]
            created = response["data"].get("created_now", False)
            self.current_backend_pub_hex = pub_hex

            msg = []
            if created:
                msg.append("Se ha creado una nueva backend_ecdh_private.pem en el backend.\n")
            else:
                msg.append("Se reutiliza la backend_ecdh_private.pem existente en el backend.\n")

            msg.append("BACKEND_ECDH_PUB_HEX:\n")
            msg.append(pub_hex)
            msg.append(
                "\n\nAVISO: esta clave pública ECDH del backend debes pegarla en el código del Source "
                "como BACKEND_ECDH_PUB_HEX."
            )

            self._set_text(self.ecdh_text, "".join(msg))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def copy_backend_pub(self):
        if not self.current_backend_pub_hex:
            messagebox.showwarning("Aviso", "Todavía no hay BACKEND_ECDH_PUB_HEX cargada")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(self.current_backend_pub_hex)
        self.root.update()
        messagebox.showinfo("Copiado", "BACKEND_ECDH_PUB_HEX copiada al portapapeles")

    def refresh_devices(self):
        try:
            response = self.rpc.request("list_devices", {})
            devices = response["data"]["devices"]

            self.devices_by_id = {dev["device_id"]: dev for dev in devices}

            for item in self.tree.get_children():
                self.tree.delete(item)

            for dev in devices:
                device_id = dev.get("device_id", "")
                short_id = device_id[:24] + "..." if len(device_id) > 24 else device_id
                active = "Sí" if dev.get("active", True) else "No"

                self.tree.insert(
                    "",
                    "end",
                    iid=device_id,
                    values=(
                        dev.get("name", ""),
                        dev.get("source_mac", ""),
                        active,
                        short_id,
                    ),
                )

            self._set_text(self.detail_text, "")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def get_selected_device(self):
        selection = self.tree.selection()
        if not selection:
            return None
        device_id = selection[0]
        return self.devices_by_id.get(device_id)

    def on_select_device(self, event=None):
        self.show_selected_device()

    def show_selected_device(self):
        dev = self.get_selected_device()
        if not dev:
            self._set_text(self.detail_text, "No hay ningún dispositivo seleccionado.")
            return

        info = []
        info.append(f"Nombre: {dev.get('name', '')}\n")
        info.append(f"MAC: {dev.get('source_mac', '')}\n")
        info.append(f"Activo: {dev.get('active', True)}\n")
        info.append(f"device_id: {dev.get('device_id', '')}\n\n")
        info.append("public_key_pem:\n")
        info.append(dev.get("public_key_pem", ""))

        self._set_text(self.detail_text, "".join(info))

    def on_register(self):
        try:
            name = self.name_var.get().strip()
            mac = normalize_mac(self.mac_var.get())
            priv_text = self.priv_var.get().strip()

            if not name:
                raise ValueError("El nombre no puede estar vacío")
            if not priv_text:
                raise ValueError("La clave privada no puede estar vacía")

            priv_d = int(priv_text)
            if priv_d <= 0:
                raise ValueError("La clave privada debe ser un entero positivo")

            public_key_pem = public_key_pem_from_priv(priv_d)
            device_id = derive_device_id(priv_d)

            entry = {
                "device_id": device_id,
                "source_mac": mac,
                "public_key_pem": public_key_pem,
                "name": name,
                "active": bool(self.active_var.get()),
            }

            response = self.rpc.request("add_or_update_device", entry)
            data = response["data"]

            self.current_backend_pub_hex = data["backend_ecdh_pub_hex"]

            msg = []
            msg.append(f"Dispositivo {data['action']} correctamente.\n\n")
            msg.append(f"Nombre: {name}\n")
            msg.append(f"MAC: {mac}\n")
            msg.append(f"Activo: {self.active_var.get()}\n")
            msg.append(f"device_id: {device_id}\n\n")
            msg.append("public_key_pem:\n")
            msg.append(public_key_pem)
            msg.append("\n\nBACKEND_ECDH_PUB_HEX para pegar en el Source:\n")
            msg.append(data["backend_ecdh_pub_hex"])
            msg.append(
                "\n\nAVISO: añade esta BACKEND_ECDH_PUB_HEX al código del dispositivo dado de alta."
            )

            self._set_text(self.result_text, "".join(msg))
            self.refresh_devices()
            self.load_backend_ecdh()

            messagebox.showinfo(
                "Alta completada",
                "Alta/actualización enviada por MQTT TLS y aplicada en el backend.\n\n"
                "Recuerda copiar la BACKEND_ECDH_PUB_HEX al Source."
            )

        except Exception as e:
            messagebox.showerror("Error en el alta", str(e))

    def deactivate_selected_device(self):
        dev = self.get_selected_device()
        if not dev:
            messagebox.showwarning("Aviso", "Selecciona primero un dispositivo")
            return

        if not messagebox.askyesno(
            "Confirmar baja",
            f"¿Dar de baja lógicamente el dispositivo '{dev.get('name', '')}'?\n\n"
            "Esto pondrá active=false, pero no lo borrará."
        ):
            return

        try:
            self.rpc.request("deactivate_device", {"device_id": dev["device_id"]})
            self.refresh_devices()
            messagebox.showinfo("Baja realizada", "Dispositivo desactivado correctamente")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def activate_selected_device(self):
        dev = self.get_selected_device()
        if not dev:
            messagebox.showwarning("Aviso", "Selecciona primero un dispositivo")
            return

        try:
            self.rpc.request("activate_device", {"device_id": dev["device_id"]})
            self.refresh_devices()
            messagebox.showinfo("Reactivación", "Dispositivo activado correctamente")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def delete_selected_device(self):
        dev = self.get_selected_device()
        if not dev:
            messagebox.showwarning("Aviso", "Selecciona primero un dispositivo")
            return

        if not messagebox.askyesno(
            "Confirmar eliminación",
            f"¿Eliminar definitivamente el dispositivo '{dev.get('name', '')}'?\n\n"
            "Esta acción borrará la entrada del trusted_devices.json en el backend."
        ):
            return

        try:
            self.rpc.request("delete_device", {"device_id": dev["device_id"]})
            self.refresh_devices()
            messagebox.showinfo("Eliminado", "Dispositivo eliminado correctamente")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_close(self):
        self.rpc.close()
        self.root.destroy()


def main():
    root = tk.Tk()
    app = TrustedDevicesAdminGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
