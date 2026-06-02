
# Gateway

Esta carpeta contiene el código del nodo Gateway, basado en ESP32 LoRa. El Gateway actúa como puente entre la comunicación LoRa Raw y el Backend ejecutado en el ordenador.

El Gateway no descifra ni verifica los mensajes. Su función es recibir el contenido enviado por los nodos Source, reconstruirlo con AlLoRa y reenviarlo al Backend por puerto serie en formato JSON.

## Orden cronológico de los archivos

## 1. `LoRa.json`

Archivo de configuración LoRa utilizado por el Gateway.

Debe ser compatible con la configuración del Source para que ambos dispositivos puedan comunicarse correctamente mediante AlLoRa.

## 2. `1NodoMain.py`

Primera versión del Gateway, pensada para trabajar con un único Source.

Su función es:

- inicializar la comunicación LoRa;
- recibir el fichero lógico enviado por el Source;
- reconstruir el payload;
- convertir el contenido recibido a hexadecimal;
- reenviarlo al Backend por puerto serie dentro de una línea JSON.

La estructura enviada al Backend incluye campos como:

- `type`;
- `source_mac`;
- `file_name`;
- `size`;
- `encoding`;
- `payload_hex`.

Esta versión se utilizó para validar el flujo básico Source-Gateway-Backend.

## 3. `Nodes.json`

Archivo de configuración utilizado en la versión multinodo.

Define los Source conocidos por el Gateway. Cada entrada puede incluir:

- nombre del nodo;
- dirección MAC;
- estado activo;
- frecuencia de consulta;
- tiempo de escucha.

Permite que el Gateway no dependa de un único Source fijo.

## 4. `MultiNodoMain.py`

Versión ampliada del Gateway para trabajar con múltiples dispositivos Source.

Su función es:

- cargar la lista de nodos desde `Nodes.json`;
- recorrer los endpoints activos;
- escuchar cada nodo durante el tiempo configurado;
- detectar nuevos payloads recibidos;
- evitar reenvíos duplicados;
- reenviar cada mensaje al Backend con su `source_mac`.

Esta versión permite aproximar el sistema a un escenario IoT más realista, donde varios nodos comparten un mismo Gateway.

## Flujo recomendado de uso

1. Configurar `LoRa.json`.
2. Probar primero el sistema con `1NodoMain.py`.
3. Configurar los nodos en `Nodes.json`.
4. Ejecutar `MultiNodoMain.py` para trabajar con varios Source.
5. Comprobar en el Backend que cada mensaje llega con el `source_mac` correcto.
