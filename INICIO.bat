@echo off
title Omni-CleanerMail - Iniciar Servidor
color 0A
echo.
echo ============================================
echo   Omni-CleanerMail - Iniciar Servidor
echo ============================================
echo.

cd /d "%~dp0"

:: Verificar Python
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python no encontrado en PATH.
    echo         Instale Python 3.10+ y agregue al PATH.
    pause
    exit /b 1
)

:: Verificar dependencias
python -c "import fastapi, uvicorn" >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Instalando dependencias...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [ERROR] Fallo al instalar dependencias.
        pause
        exit /b 1
    )
)

:: Detener instancias previas
echo [INFO] Deteniendo instancias previas...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq Omni-CleanerMail*" >nul 2>&1
for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING" 2^>nul') do taskkill /F /PID %%p >nul 2>&1
for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":8791" ^| findstr "LISTENING" 2^>nul') do taskkill /F /PID %%p >nul 2>&1
timeout /t 1 /nobreak >nul

:: Iniciar servidor
echo [INFO] Iniciando Omni-CleanerMail en http://127.0.0.1:8791 ...
echo.
start "Omni-CleanerMail" /min cmd /c "cd /d "%~dp0" && python scripts/run.py --port 8791"

:: Esperar a que levante
echo [INFO] Esperando respuesta del servidor...
set /a retries=0
:waitloop
timeout /t 1 /nobreak >nul
set /a retries+=1
if %retries% geq 20 (
    echo [ERROR] El servidor no respondio en 20 segundos.
    echo         Revise la consola de Omni-CleanerMail.
    pause
    exit /b 1
)
curl -s http://127.0.0.1:8791/api/health >nul 2>&1
if %errorlevel% neq 0 goto waitloop

echo [OK] Servidor iniciado correctamente.
echo.
echo ============================================
echo   URL:   http://127.0.0.1:8791
echo   Login: admin / admin123
echo ============================================
echo.

:: Abrir navegador
start http://127.0.0.1:8791

pause
