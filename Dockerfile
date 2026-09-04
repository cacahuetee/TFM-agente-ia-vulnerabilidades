# Imagen reproducible de la herramienta (para el anexo y despliegue).
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501
# Arranca la interfaz web
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]
