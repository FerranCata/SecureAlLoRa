
# Firmware

Esta carpeta contiene el firmware base utilizado para preparar las placas ESP32 LoRa antes de cargar los scripts principales del proyecto.

## Archivos

## 1. `firmware.bin`

Firmware que debe cargarse en las placas LilyGO ESP32 LoRa para poder ejecutar el entorno necesario del proyecto.

Este paso se realiza antes de copiar los archivos del Source o del Gateway. Permite preparar la placa para trabajar con MicroPython y AlLoRa según la configuración empleada en el TFG.

## Uso general

El procedimiento habitual consiste en:

1. Conectar la placa al ordenador.
2. Activar el modo de arranque si es necesario.
3. Borrar la memoria flash.
4. Escribir `firmware.bin` en la placa.
5. Reiniciar la placa.
6. Copiar los archivos correspondientes de `Source` o `Gateway`.

Ejemplo general:

```bash
esptool.py --chip esp32s3 --port /dev/ttyACM0 erase_flash
esptool.py --chip esp32s3 --port /dev/ttyACM0 write_flash -z 0x0 firmware.bin
```

El puerto puede variar según el equipo utilizado.
