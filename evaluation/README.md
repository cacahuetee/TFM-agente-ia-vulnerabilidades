# Evaluación y comparativa de modelos

Marco de evaluación reproducible (objetivos 7 y 8 del TFM).

## Qué mide

Métricas objetivas y deterministas, sin juicio humano ni de otro modelo:

- **Cobertura**: proporción de elementos esperados (ground truth) que aparecen
  en la respuesta. Mide la completitud del análisis.
- **CVEs no fundamentados**: identificadores CVE mencionados que NO estaban en
  los datos aportados al modelo. Indicador de contenido inventado (alucinación).
- **Latencia**: tiempo de respuesta.
- **Tokens** y **coste estimado**: consumo por respuesta (el coste usa los
  precios de `config/models.yaml`, que debes verificar en openrouter.ai).

## Casos de prueba

En `cases/` hay cuatro escaneos con su ground truth en `ground_truth.json`:

1. `case01_metasploitable` — host muy vulnerable (servicios antiguos + un CVE).
2. `case02_webserver` — servidor web con Apache y SSH.
3. `case03_windows` — host Windows con SMB y RDP.
4. `case04_limpio` — host actualizado (control de falsos positivos).

Puedes añadir más casos: coloca el XML en `cases/` y su entrada en
`ground_truth.json`.

## Cómo ejecutar

```bash
# 1. Prueba sin red ni API (comprueba que todo funciona)
python main.py evaluate --mock

# 2. Real y gratis (un solo modelo gratuito)
python main.py evaluate --models free

# 3. Comparativa completa (requiere saldo en OpenRouter)
python main.py evaluate --models deepseek,qwen,llama,mistral
```

Los resultados se guardan en `evaluation/resultados/`:
- `resultados_detalle.csv` — una fila por (caso, modelo).
- `resultados_resumen.csv` — medias y totales por modelo.

También puedes verlos en la interfaz web, en la sección
«Resultados de la evaluación de modelos».
