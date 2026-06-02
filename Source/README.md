
# Source

Esta carpeta contiene los programas que se ejecutan en el nodo emisor Source, basado en ESP32 LoRa. El Source genera los datos de aplicación, construye el mensaje y aplica el modo de seguridad correspondiente antes de enviarlo al Gateway mediante LoRa Raw y AlLoRa.

## Orden cronológico de los archivos

## 1. `LoRa.json`

Archivo de configuración LoRa utilizado por el Source.

Define parámetros necesarios para que el nodo pueda comunicarse con el Gateway mediante AlLoRa. Debe ser coherente con la configuración utilizada en el Gateway.

## 2. `SSmain.py`

Primera versión del Source. Corresponde al modo **sin seguridad**.

Su función es:

- generar un mensaje JSON con datos de ejemplo;
- incluir campos como `device_id`, `msg_type`, `timestamp`, `counter` y `data`;
- serializar el mensaje;
- enviarlo mediante AlLoRa al Gateway.

En este modo el payload viaja en claro. Sirve como base funcional para validar la comunicación LoRa y el reenvío al Backend.

## 3. `AESmain.py`

Versión del Source con cifrado AES.

Su función es:

- construir el mismo mensaje lógico que en el modo sin seguridad;
- derivar una clave AES;
- generar un `nonce`;
- cifrar el mensaje mediante AES-CTR;
- enviar el payload con estructura `nonce || ciphertext`.

Este modo protege la confidencialidad del contenido, pero todavía no autentica el origen ni verifica la integridad del mensaje.

## 4. `ecdsa_p256.py`

Módulo auxiliar para operaciones de firma digital ECC sobre la curva P-256.

Su función es proporcionar las operaciones necesarias para que el Source pueda:

- trabajar con una clave privada ECC;
- obtener la clave pública correspondiente;
- firmar mensajes;
- construir el material criptográfico necesario para el modo ECC.

Este módulo se utiliza en `ECCmain.py` y `ECDHmain.py`.

## 5. `ECCmain.py`

Versión del Source con **ECC + AES**.

Su función es:

- generar el mensaje de aplicación;
- calcular un `device_id` asociado a la clave pública;
- incluir `boot_id` y `counter`;
- construir una representación canónica del mensaje;
- firmar esa representación con ECC;
- añadir la firma al mensaje;
- cifrar el mensaje completo con AES;
- enviarlo al Gateway.

Este modo añade autenticación e integridad sobre el cifrado AES.

## 6. `ecdh_p256.py`

Módulo auxiliar para operaciones ECDH sobre la curva P-256.

Su función es permitir que el Source:

- genere material ECDH efímero;
- calcule una clave pública efímera;
- use la clave pública ECDH del Backend;
- derive un secreto compartido;
- obtenga una clave AES de sesión.

Este módulo se utiliza en `ECDHmain.py`.

## 7. `ECDHmain.py`

Versión final del Source con **ECDH + ECC + AES**.

Su función es:

- generar datos de aplicación;
- generar material ECDH efímero;
- calcular la clave AES de sesión mediante ECDH;
- incluir la clave pública efímera en el mensaje;
- firmar la representación canónica del mensaje;
- cifrar el contenido con AES-CTR;
- enviar el payload con estructura `ecdh_pub_source || nonce || ciphertext`.

Este modo combina confidencialidad, autenticación, integridad, derivación de clave de sesión y protección anti-replay mediante `boot_id` y `counter`.

## Flujo recomendado de uso

1. Configurar `LoRa.json`.
2. Probar comunicación básica con `SSmain.py`.
3. Probar cifrado con `AESmain.py`.
4. Preparar claves ECC y registrar la clave pública en el Backend.
5. Probar firma y cifrado con `ECCmain.py`.
6. Generar la clave pública ECDH del Backend.
7. Copiar `BACKEND_ECDH_PUB_HEX` en `ECDHmain.py`.
8. Ejecutar `ECDHmain.py` para el modo completo.
