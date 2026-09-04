# Montaje del laboratorio de pruebas (aislado)

Todo el trabajo experimental debe realizarse en un entorno **aislado**, sin
acceso a Internet ni a la red real, y **nunca** contra sistemas de terceros.

## Componentes recomendados
- **Hipervisor**: VirtualBox o VMware.
- **Máquina atacante**: Kali Linux (trae Nmap).
- **Objetivos vulnerables (uso educativo)**: Metasploitable 2/3, DVWA, VulnHub.

## Red
- Crear una red **solo-anfitrión (host-only)** o **interna**: las máquinas se
  ven entre sí pero quedan aisladas del exterior.
- Anota el rango (p. ej. `192.168.56.0/24`).

## Generar datos de entrada
```bash
nmap -sV -oX salida.xml 192.168.56.101
```
Luego se procesa `salida.xml` con la herramienta (CLI o Streamlit).

## Buenas prácticas
- Snapshot de cada VM tras instalarla.
- No expongas estas máquinas a la red real.
- Documenta cada escaneo (comando, fecha, objetivo) para la trazabilidad.
