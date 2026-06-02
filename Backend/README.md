

Esta carpeta contiene los programas Python ejecutados en el ordenador que actúa como Backend. El Backend recibe por puerto serie los mensajes reenviados por el Gateway, reconstruye el payload, aplica las operaciones de seguridad necesarias y, en las versiones finales, publica los datos válidos mediante MQTT sobre TLS.

## Orden cronológico de los archivos

## 1. `BackendSS.py`

Primer backend del proyecto. Corresponde al modo **sin seguridad**.

Su función es:

- abrir el puerto serie;
- leer las líneas JSON enviadas por el Gateway;
- extraer `payload_hex`;
- convertirlo a bytes;
- decodificar el payload como JSON;
- aplicar un control anti-replay básico mediante `counter`;
- registrar o mostrar los datos recibidos.

En este modo no hay cifrado, firma digital ni derivación de claves. Sirve como línea base para comprobar que la arquitectura Source-Gateway-Backend funciona correctamente.

## 2. `BackendAES.py`

Backend correspondiente al modo **AES**.

Su función es:

- recibir el payload cifrado desde el Gateway;
- separar `nonce` y `ciphertext`;
- derivar una clave AES de 128 bits;
- descifrar el contenido;
- recuperar el JSON original;
- aplicar un control anti-replay básico.

Este modo introduce confidencialidad del payload. El Gateway sigue sin interpretar el contenido y solo reenvía los datos al Backend.

## 3. `make_public_pem.py`

Script auxiliar utilizado para obtener la clave pública ECC del Source a partir de su clave privada.

Su función es:

- construir una clave ECC sobre la curva P-256;
- obtener la clave pública asociada;
- exportarla en formato PEM;
- facilitar su incorporación al registro de dispositivos confiables.

Este archivo se usa antes de ejecutar el modo ECC, porque el Backend necesita conocer la clave pública del Source para verificar sus firmas.

## 4. `BackendECC.py`

Backend correspondiente al modo **ECC + AES**.

Su función es:

- recibir el payload cifrado;
- descifrarlo con AES;
- reconstruir el mensaje interno;
- consultar `trusted_devices.json`;
- recuperar la clave pública del dispositivo;
- reconstruir la representación canónica del mensaje;
- verificar la firma ECC;
- aplicar control anti-replay;
- aceptar o rechazar el mensaje.

Este modo añade autenticación e integridad sobre el modo AES. El mensaje ya no se acepta solo porque pueda descifrarse, sino porque además debe estar firmado por un dispositivo autorizado.

## 5. `trusted_devices.json`

Fichero de configuración que almacena los dispositivos confiables.

Cada entrada contiene normalmente:

- `device_id`;
- `source_mac`;
- `public_key_pem`;
- `name`;
- `active`.

Este registro permite al Backend decidir qué dispositivos pueden enviar mensajes válidos. También permite activar, desactivar o eliminar dispositivos sin modificar la lógica principal del Backend.

## 6. `gen_backend_ecdh.py`

Script auxiliar para generar el par de claves ECDH del Backend.

Su función es:

- generar una clave privada ECDH sobre P-256;
- guardarla en `backend_ecdh_private.pem`;
- mostrar por pantalla la clave pública del Backend en formato hexadecimal.

La clave pública generada debe copiarse en el firmware del Source ECDH como `BACKEND_ECDH_PUB_HEX`.

## 7. `backend_ecdh_private.pem`

Clave privada ECDH persistente del Backend.

Se utiliza en el modo ECDH para calcular el secreto compartido con el Source. A partir de ese secreto se deriva la clave AES de sesión.

Importante: este archivo no debería subirse a un repositorio público si contiene una clave real. En GitHub conviene usar un archivo de ejemplo y mantener la clave real fuera del repositorio.

## 8. `BackendECDH.py`

Backend final del sistema. Corresponde al modo **ECDH + ECC + AES** y a la integración con MQTT TLS.

Su función es:

- recibir el payload desde el Gateway;
- separar la clave pública efímera ECDH del Source;
- separar `nonce` y `ciphertext`;
- calcular el secreto compartido ECDH;
- derivar la clave AES de sesión;
- descifrar el mensaje;
- comprobar que la clave pública efímera coincide con la incluida en el mensaje firmado;
- verificar la firma ECC;
- aplicar anti-replay usando `boot_id` y `counter`;
- validar el dispositivo en `trusted_devices.json`;
- publicar datos válidos mediante MQTT TLS;
- procesar solicitudes de administración del registro de confianza.

Es la versión más completa del Backend.

## 9. `trusted_devices_admin_GUI.py`

Interfaz gráfica de administración de dispositivos confiables.

Su función es:

- conectarse al broker MQTT mediante TLS;
- enviar solicitudes administrativas al Backend;
- listar dispositivos registrados;
- añadir o actualizar dispositivos;
- activar o desactivar nodos;
- eliminar dispositivos;
- consultar la clave pública ECDH del Backend.

La GUI no modifica directamente `trusted_devices.json`. En su lugar, envía peticiones al Backend mediante MQTT TLS. Esto mantiene al Backend como único componente autorizado para cambiar el registro de confianza.

## Flujo recomendado de uso

1. Ejecutar primero `BackendSS.py` para validar comunicación básica.
2. Ejecutar `BackendAES.py` para probar cifrado AES.
3. Usar `make_public_pem.py` para preparar la clave pública del Source.
4. Configurar `trusted_devices.json`.
5. Ejecutar `BackendECC.py` para probar firma ECC + AES.
6. Ejecutar `gen_backend_ecdh.py` para generar la clave ECDH del Backend.
7. Copiar la clave pública ECDH al Source.
8. Ejecutar `BackendECDH.py` para el modo completo.
9. Ejecutar `trusted_devices_admin_GUI.py` para administrar dispositivos por MQTT TLS.
