@echo off
title Omni-CleanerMail - Detener Servidor
color 0C
echo.
echo ============================================
echo   Omni-CleanerMail - Detener Servidor
echo ============================================
echo.

cd /d "%~dp0"

echo [INFO] Buscando procesos de Omni-CleanerMail...

:: Matar por ventana
taskkill /F /FI "WINDOWTITLE eq Omni-CleanerMail*" >nul 2>&1

:: Matar por puerto 8791
for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":8791" ^| findstr "LISTENING" 2^>nul') do (
    echo [INFO] Deteniendo proceso PID %%p en puerto 8791...
    taskkill /F /PID %%p >nul 2>&1
)

:: Matar por puerto 8000 (por si acaso)
for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING" 2^>nul') do (
    echo [INFO] Deteniendo proceso PID %%p en puerto 8000...
    taskkill /F /PID %%p >nul 2>&1
)

timeout /t 2 /nobreak >nul

:: Verificar que no quede nada
netstat -aon | findstr ":8791" | findstr "LISTENING" >nul 2>&1
if %errorlevel% equ 0 (
    echo [ADVERTENCIA] El proceso en puerto 8791 sigue activo.
) else (
    echo [OK] Servidor detenido correctamente.
)

echo.
pause
