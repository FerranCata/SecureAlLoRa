
# MQTT_TLS

Esta carpeta contiene la configuración necesaria para ejecutar el broker Mosquitto con TLS. MQTT se utiliza en el proyecto para publicar los datos validados por el Backend y para gestionar los dispositivos confiables mediante la GUI de administración.

## Archivos principales

## 1. `mosquitto_tls.conf`

Archivo de configuración de Mosquitto para activar MQTT sobre TLS.

Su función es:

- abrir el listener seguro en el puerto 8883;
- indicar el certificado de la autoridad certificadora;
- indicar el certificado y clave del servidor;
- exigir certificado de cliente;
- desactivar conexiones anónimas.

Esta configuración permite que solo clientes autenticados puedan conectarse al broker.


## Flujo recomendado de uso

1. Crear la autoridad certificadora local.
2. Generar certificado y clave del servidor Mosquitto.
3. Generar certificado y clave del cliente Backend.
4. Generar certificado y clave del cliente de administración.
5. Configurar `mosquitto_tls.conf`.
6. Iniciar Mosquitto con esa configuración.
7. Ejecutar el Backend.
8. Ejecutar la GUI de administración si se necesita gestionar dispositivos.


