@echo off
REM ============================================================
REM  Omni-CleanerMail - Instalacion en Windows Server
REM  Crea venv, instala dependencias, y registra la tarea de arranque.
REM
REM  Requisitos: Python 3.11+ en PATH.
REM  USO (como administrador):
REM      scripts\install_windows.bat
REM ============================================================
setlocal
cd /d "%~dp0.."
set BASE=%CD%
set VENV=%BASE%\venv

echo [1/4] Creando entorno virtual en %VENV% ...
if not exist "%VENV%\Scripts\python.exe" (
    python -m venv "%VENV%" || goto :error
)
"%VENV%\Scripts\python.exe" -m pip install --upgrade pip
"%VENV%\Scripts\python.exe" -m pip install -r requirements.txt || goto :error

echo [2/4] Copiando plantilla de configuracion (.env) si no existe ...
if not exist "%BASE%\.env" (
    copy /Y "%BASE%\.env.example" "%BASE%\.env" >nul
    echo       Se creo .env. EDITALO con LOOK_SMTP_* y, si la maquina no es
    echo       la que aloja el gateway, pon LOOK_BIND=0.0.0.0 (no recomendado).
) else (
    echo       .env ya existe, no se toca.
)

echo [3/4] Creando tarea programada "Omni-CleanerMail" (inicio con el sistema) ...
schtasks /Create /TN "Omni-CleanerMail" /TR "\"%VENV%\Scripts\pythonw.exe\" \"%BASE%\scripts\servicio.py\"" /SC ONSTART /RU SYSTEM /F || goto :error

echo [4/4] Exclusiones de antivirus (Kaspersky/Defender) ...
echo.
echo IMPORTANTE: EXCLUYE de la proteccion en tiempo real (antivirus/host):
echo   - %BASE%\app\data
echo   - %BASE%\venv
echo   - %BASE%\.env
echo En Windows Defender puedes ejecutar:
echo   Add-MpPreference -ExclusionPath "%BASE%\app\data"
echo   Add-MpPreference -ExclusionPath "%BASE%\venv"
echo En Kaspersky Endpoint Security: Ajustes ^> Amenazas y exclusiones ^> Variables/Gestion.
echo.
echo NOTA: las exclusiones del gate de KSMG real (carpeta EML_WATCH, receptor SMTP)
echo       se gestionan desde el panel KSMG de la aplicacion.
echo.
echo [OK] Instalacion completada.
echo      Comprueba el estado con:  schtasks /Query /TN "Omni-CleanerMail"
echo      Arranque manual:           "%VENV%\Scripts\python.exe" scripts\run.py --no-seed
echo      Acceso web: http://127.0.0.1:%LOOK_PORT%   (LOOK_PORT, def. 8000)
pause
goto :eof

:error
echo [ERROR] Fallo en el paso anterior. Revisa la salida. >&2
exit /b 1