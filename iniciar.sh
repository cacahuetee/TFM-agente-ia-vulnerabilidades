#!/usr/bin/env bash
# Lanzador para Mac y Linux.
#   Terminal:  bash iniciar.sh      (o  chmod +x iniciar.sh && ./iniciar.sh)
cd "$(dirname "$0")"

if [ ! -f "requirements.txt" ]; then
  echo ""
  echo "No encuentro los archivos del proyecto."
  echo "Probablemente abriste este archivo sin descomprimir el ZIP."
  echo "Descomprime el zip, entra en la carpeta del proyecto y vuelve a ejecutar este script."
  echo ""
  read -p "Pulsa Enter para salir..."
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo ""
  echo "No se ha encontrado Python."
  echo "Mac:   https://www.python.org/downloads/   (o: brew install python3)"
  echo "Linux: sudo apt install python3 python3-venv python3-pip"
  echo "Despues vuelve a ejecutar este script."
  echo ""
  read -p "Pulsa Enter para salir..."
  exit 1
fi

if [ ! -f ".venv/bin/python" ]; then
  echo "Creando el entorno por primera vez..."
  python3 -m venv .venv
fi

if ! .venv/bin/python -c "import streamlit" >/dev/null 2>&1; then
  echo "Instalando dependencias. Esto puede tardar un par de minutos..."
  .venv/bin/python -m pip install --upgrade pip >/dev/null
  .venv/bin/python -m pip install -r requirements.txt
fi

echo ""
echo "Abriendo la herramienta en tu navegador..."
echo "La web te pedira tu nombre y tu clave de OpenRouter."
echo "(Para cerrarla, cierra esta ventana.)"
echo ""
.venv/bin/python -m streamlit run app.py
