# TFG: Comunicación IoT segura sobre AlLoRa/LoRa con MicroPython

## Descripción

Este proyecto desarrolla e integra una capa de seguridad sobre un sistema de comunicación IoT basado en **AlLoRa/LoRa**, ejecutado en dispositivos embebidos con **MicroPython** y conectado a un **backend en Python**.

El objetivo principal del trabajo es estudiar el coste real de añadir mecanismos de seguridad a una comunicación LoRa de bajo consumo, comparando tres modos de funcionamiento:

- **Sin seguridad (SS)**
- **AES**
- **ECC + AES**

El sistema implementado permite transmitir datos de sensores desde un nodo **Source**, recibirlos en el lado de consulta (**Requester/Gateway**) y procesarlos en un backend capaz de validar, descifrar y publicar la información mediante **MQTT TLS**.

## Contexto

AlLoRa es una capa avanzada sobre LoRa orientada a la transferencia de contenido, con una arquitectura modular basada en nodos **Source**, **Requester** y **Gateway**. En una configuración básica, el Source genera los datos y el Requester los solicita. Cuando se trabaja con múltiples nodos Source, el papel de consulta pasa a ser el de un Gateway.

Sobre esta base, este TFG añade una capa de seguridad aplicada al contenido útil de los mensajes, con el fin de evaluar el impacto real en tamaño, fragmentación, validación y coste de transmisión.

## Objetivos

### Objetivo general

Diseñar, implementar y evaluar un sistema de comunicación IoT seguro sobre AlLoRa/LoRa en dispositivos con MicroPython.

### Objetivos específicos

- Implementar tres modos de transmisión: **SS**, **AES** y **ECC+AES**.
- Diseñar el formato de mensaje seguro entre nodo y backend.
- Incorporar mecanismos de **confidencialidad**, **integridad**, **autenticidad** y **protección anti-replay**.
- Validar experimentalmente el funcionamiento del sistema.
- Comparar el coste técnico de cada esquema de seguridad.
- Estudiar la viabilidad del sistema en entornos IoT con recursos limitados.

## Arquitectura del sistema

El sistema se compone de los siguientes elementos:

- **Nodo Source**: dispositivo embebido que genera la telemetría y la transmite mediante AlLoRa.
- **Nodo de consulta**: puede actuar como **Requester** si trabaja con un único Source, o como **Gateway** si gestiona varios nodos.
- **Backend en Python**: recibe los mensajes, los descifra, verifica su validez y publica la información procesada.
- **Broker MQTT TLS**: canal de publicación segura de los datos.

### Esquema general

[Sensor / Data Source]
        |
        v
 [Source Node]
   MicroPython
   AlLoRa + LoRa
        |
        v
[Requester / Gateway]
        |
        v
 [Backend Python]
   - recepción
   - descifrado
   - verificación
   - anti-replay
   - publicación MQTT TLS
        |
        v
   [Broker MQTT]

   
