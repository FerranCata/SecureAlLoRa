
# Sistema IoT LoRa Raw con seguridad AES, ECC, ECDH y MQTT TLS

Este repositorio contiene el código desarrollado para un TFG centrado en la implementación y análisis de una arquitectura IoT segura basada en LoRa Raw. El sistema permite comparar distintos modos de comunicación, desde una transmisión sin seguridad hasta una versión con cifrado AES, firma ECC, derivación de clave mediante ECDH, control anti-replay, gestión de dispositivos confiables y publicación mediante MQTT sobre TLS.

El objetivo principal del proyecto no es sustituir soluciones estandarizadas como LoRaWAN, sino construir una prueba de concepto controlada que permita estudiar cómo afectan distintos mecanismos de seguridad al tamaño del payload, al procesamiento del mensaje y a la comunicación entre nodos embebidos y backend.

## Arquitectura general

La arquitectura se organiza en cinco bloques principales:

```text
Source  ->  Gateway  ->  Backend  ->  MQTT TLS
                         ^
                         |
                      GUI Admin
```

- `Source`: nodo emisor basado en ESP32 LoRa. Genera los datos, aplica el modo de seguridad correspondiente y transmite el payload mediante LoRa Raw usando AlLoRa.
- `Gateway`: nodo intermedio basado en ESP32 LoRa. Recibe mensajes mediante LoRa, reconstruye el contenido con AlLoRa y lo reenvía al Backend por puerto serie.
- `Backend`: aplicación Python que recibe los mensajes, descifra, verifica firmas, aplica anti-replay, valida dispositivos confiables y publica datos válidos.
- `MQTT_TLS`: configuración del broker Mosquitto con TLS y certificados.
- `GUI Admin`: interfaz gráfica para administrar dispositivos confiables mediante MQTT TLS.

## Estructura del repositorio

```text
.
├── Backend
│   ├── BackendAES.py
│   ├── BackendECC.py
│   ├── backend_ecdh_private.pem
│   ├── BackendECDH.py
│   ├── BackendSS.py
│   ├── gen_backend_ecdh.py
│   ├── make_public_pem.py
│   ├── trusted_devices_admin_GUI.py
│   └── trusted_devices.json
├── Firmware
│   └── firmware.bin
├── Gateway
│   ├── 1NodoMain.py
│   ├── LoRa.json
│   ├── MultiNodoMain.py
│   └── Nodes.json
├── MQTT_TLS
│   ├── certs
│   │   ├── admin_client.crt
│   │   ├── admin_client.csr
│   │   ├── admin_client.key
│   │   ├── ca.crt
│   │   ├── ca.key
│   │   ├── ca.srl
│   │   ├── client.crt
│   │   ├── client.csr
│   │   ├── client.key
│   │   ├── server.crt
│   │   ├── server.csr
│   │   └── server.key
│   └── mosquitto_tls.conf
└── Source
    ├── AESmain.py
    ├── ECCmain.py
    ├── ECDHmain.py
    ├── ecdh_p256.py
    ├── ecdsa_p256.py
    ├── LoRa.json
    └── SSmain.py
```

## Orden cronológico de desarrollo

El proyecto está organizado de forma progresiva. El orden lógico de evolución es el siguiente:

1. Carga del firmware base en las placas ESP32 LoRa.
2. Implementación de comunicación básica Source-Gateway-Backend sin seguridad.
3. Incorporación del cifrado AES en el payload.
4. Incorporación de firma ECC para autenticación e integridad.
5. Gestión de dispositivos confiables en el Backend.
6. Ampliación a múltiples nodos Source.
7. Incorporación de ECDH para derivación de clave de sesión.
8. Integración con MQTT sobre TLS.
9. Desarrollo de GUI de administración por MQTT TLS.

## Modos de funcionamiento

| Modo | Source | Backend | Propósito |
|---|---|---|---|
| Sin seguridad | `Source/SSmain.py` | `Backend/BackendSS.py` | Comunicación base en claro |
| AES | `Source/AESmain.py` | `Backend/BackendAES.py` | Confidencialidad del payload |
| ECC + AES | `Source/ECCmain.py` | `Backend/BackendECC.py` | Confidencialidad, autenticación e integridad |
| ECDH + ECC + AES | `Source/ECDHmain.py` | `Backend/BackendECDH.py` | Derivación de clave de sesión, autenticación, integridad y cifrado |

## Requisitos generales

En el Backend se requiere Python 3 y varias dependencias:

```bash
pip install pyserial pycryptodome paho-mqtt
```

Para el broker MQTT con TLS se utiliza Mosquitto:

```bash
sudo apt install mosquitto mosquitto-clients
```

En los nodos ESP32 LoRa se utiliza MicroPython y la librería AlLoRa.

## Documentación por carpetas

Cada carpeta principal incluye su propio `README.md`:

- `Backend/README.md`: explicación de los backends y scripts auxiliares.
- `Source/README.md`: explicación de los modos del nodo emisor.
- `Gateway/README.md`: explicación del gateway de un nodo y multinodo.
- `MQTT_TLS/README.md`: explicación de certificados y configuración Mosquitto.
- `Firmware/README.md`: explicación del firmware base de las placas.
