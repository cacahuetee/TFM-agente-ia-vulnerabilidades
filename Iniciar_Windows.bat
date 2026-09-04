@echo off
chcp 65001 >nul
pushd "%~dp0"
title Agente de auditoria TFM

echo ============================================
echo   Agente de auditoria TFM - iniciando
echo ============================================
echo Carpeta: %CD%
echo.

if not exist "requirements.txt" goto :sin_archivos

where python >nul 2>nul
if errorlevel 1 goto :sin_python

echo Python encontrado:
python --version
echo.

if not exist ".venv\Scripts\python.exe" (
  echo Creando el entorno por primera vez, espera un momento
  python -m venv .venv
  if errorlevel 1 goto :error_venv
)

".venv\Scripts\python.exe" -c "import streamlit" >nul 2>nul
if errorlevel 1 (
  echo Instalando dependencias, esto puede tardar unos minutos
  ".venv\Scripts\python.exe" -m pip install --upgrade pip
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  if errorlevel 1 goto :error_deps
)

echo.
echo Abriendo la herramienta en tu navegador
echo La web te pedira tu nombre y tu clave de OpenRouter.
echo Para cerrarla, cierra esta ventana
echo.
".venv\Scripts\python.exe" -m streamlit run app.py
goto :fin

:sin_archivos
echo [ERROR] No encuentro requirements.txt en esta carpeta.
echo Extrae el zip y entra en la carpeta tfm antes de abrir el lanzador.
goto :fin

:sin_python
echo [ERROR] No se ha encontrado Python.
echo Instalalo desde https://www.python.org/downloads/
echo Durante la instalacion marca "Add Python to PATH".
goto :fin

:error_venv
echo [ERROR] No se pudo crear el entorno virtual.
goto :fin

:error_deps
echo [ERROR] Fallo al instalar las dependencias.
goto :fin

:fin
echo.
echo ============================================
echo Proceso terminado. Puedes cerrar esta ventana.
echo ============================================
pause >nul
popd
