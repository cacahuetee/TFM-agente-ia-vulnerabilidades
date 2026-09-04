# Agente de IA para el apoyo al análisis de vulnerabilidades y la respuesta ante incidentes

Trabajo Fin de Máster · Elsa Ferreras Patón · Escuela Internacional de Posgrados (2025/2026)

Herramienta basada en un agente de IA que orquesta varios modelos de lenguaje a
través de OpenRouter e integra fuentes técnicas de referencia (NVD/CVE, MITRE
ATT&CK y OWASP) para asistir en tareas de auditoría de seguridad: interpretación
de escaneos (Nmap, Nessus), análisis de logs, priorización de vulnerabilidades y
generación de informes.

## Puesta en marcha rápida

**Requisito único: Python 3.** Descárgalo de https://www.python.org/downloads/
(en Windows, marca "Add Python to PATH" al instalar).

1. Descomprime el proyecto (o clónalo).
2. Windows: doble clic en `Iniciar_Windows.bat`. Mac/Linux: `bash iniciar.sh`.
3. La primera vez se instala todo solo (unos minutos). Se abre el navegador.
4. Elige tu **usuario** (o crea el tuyo) e introduce tu **clave de OpenRouter**.
5. Pulsa **«Probar con el escaneo de ejemplo»** para ver el flujo completo en segundos.

Guía paso a paso, sin tecnicismos: [`COMO_USARLO.txt`](COMO_USARLO.txt).

Arranque manual (alternativa):

    python -m venv .venv
    source .venv/bin/activate            # Windows: .venv\Scripts\activate
    pip install -r requirements.txt
    streamlit run app.py

## Usuarios y clave de API

- **Usuarios.** Al arrancar, la web pregunta quién eres. La primera vez se crea
  el usuario; después basta con elegirlo. El nombre firma los informes que se
  descargan. Se guarda en `data/usuarios.json` (solo en el equipo local).
- **Clave de OpenRouter.** Cada usuario introduce la suya una sola vez. Se valida
  contra la API y **la herramienta nunca la escribe en un archivo**: se conserva en
  el `localStorage` del navegador del usuario, asociada a su nombre, de modo que
  ni una recarga ni una nueva visita la vuelven a pedir. El botón «Borrar mi
  clave» la elimina del navegador. Sin clave se pueden ver servicios, CVEs y
  priorización, pero no la interpretación de la IA.
- Para la línea de comandos o Docker, la clave puede darse como variable de
  entorno `OPENROUTER_API_KEY` o en un `.env` (ver `.env.example`).

## Interfaz web

Cuatro pestañas: **Análisis de escaneo** (resumen en tarjetas, servicios y CVEs en
color, priorización, contexto ATT&CK/OWASP, interpretación por IA e informe firmado),
**Análisis de logs**, **Evaluación de modelos** (con estimación de coste previa) y
**Mi historial** (cada análisis del usuario, con su informe descargable). Botones de
ejemplo en las dos primeras. Tema visual en `.streamlit/config.toml`; logo opcional en
`assets/logo.png`.

## Funcionalidades

- Entradas Nmap (XML) y Nessus (.nessus) con detección automática del formato.
- Enriquecimiento con CVEs de la NVD (con caché local) y criticidad en color con CVSS.
- Priorización de vulnerabilidades por riesgo.
- Contexto MITRE ATT&CK y OWASP asociado a cada servicio detectado.
- Interpretación por un modelo de lenguaje, con selector de modelo y selección
  dinámica por métricas (calidad, latencia o coste).
- Análisis de logs (syslog y JSON) desde la web y la CLI.
- Modelo local opcional (Ollama) para preservar la confidencialidad.
- Informes en HTML (imprimible a PDF) y Markdown, firmados por el usuario.
- Historial de análisis por usuario (`data/historial/`).
- Marco de evaluación con 4 casos de prueba y métricas objetivas, ejecutable
  desde la web o la CLI, robusto ante modelos no disponibles.
- Reintentos ante límites (429) y errores de red; trazabilidad de cada llamada
  en `data/logs/runs.jsonl`.
- Tests automáticos (pytest) y Dockerfile.

## Estructura del proyecto

    app.py                  Interfaz web (Streamlit)
    main.py                 Interfaz de línea de comandos
    Iniciar_Windows.bat     Lanzador para Windows (doble clic)
    iniciar.sh              Lanzador para Mac y Linux
    COMO_USARLO.txt         Guía de uso sin tecnicismos
    requirements.txt        Dependencias Python
    Dockerfile              Imagen reproducible (opcional)
    .streamlit/config.toml  Tema visual de la web
    assets/                 Logo opcional (assets/logo.png)
    config/models.yaml      Modelos disponibles y enrutado por tarea
    prompts/                Plantillas de instrucciones al modelo
    templates/              Plantillas Jinja2 de los informes (HTML, Markdown)
    src/
      config.py             Configuración (clave solo en memoria, YAML de modelos)
      users.py              Registro local de usuarios
      browser_storage.py    Persistencia de sesión en el navegador (F5 no borra nada)
      history.py            Historial de análisis por usuario
      schema.py             Modelo de datos normalizado (hosts, servicios, CVEs)
      display.py            Salida en color para la consola
      trace.py              Trazabilidad de llamadas a modelos
      parsers/              Nmap, Nessus, logs y despachador automático
      knowledge/            NVD/CVE y mapeo MITRE ATT&CK / OWASP
      llm/                  Clientes OpenRouter y Ollama, router y factoría
      tasks/                Interpretación de escaneos, análisis de logs, priorización
      reporting/            Generación de informes
    evaluation/             Casos de prueba, ground truth, métricas y runner
      resultados/           CSV con los resultados de la última evaluación
    data/samples/           Escaneos y logs de ejemplo
    data/cache/             Caché local de consultas a la NVD
    docs/                   Documentación adicional
    tests/                  Pruebas unitarias (pytest)

## Línea de comandos

    python main.py parse      data/samples/sample_nmap.xml
    python main.py enrich     data/samples/sample_nmap.xml --offline
    python main.py prioritize data/samples/sample_nmap.xml --offline
    python main.py interpret  data/samples/sample_nmap.xml --enrich
    python main.py logs       data/samples/sample_logs.txt
    python main.py evaluate   --mock

## Pruebas

    python -m pytest tests/ -q

## Docker (opcional)

    docker build -t tfm-agente .
    docker run -p 8501:8501 tfm-agente

## Aviso

Uso educativo. Analiza únicamente escaneos de sistemas sobre los que tengas
autorización. Las conclusiones generadas con apoyo de IA deben ser revisadas
por un profesional antes de tomar decisiones.
