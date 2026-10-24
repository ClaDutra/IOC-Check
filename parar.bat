@echo off
rem ============================================================
rem  IOC Check - encerra o servidor que roda em segundo plano
rem  (o mesmo que o botao "Encerrar IOC Check" da barra lateral)
rem ============================================================
setlocal
if not defined PORTA set "PORTA=5000"
set "ACHOU="
for /f "tokens=5" %%p in ('netstat -ano ^| findstr /r /c:":%PORTA% .*LISTENING"') do (
    taskkill /PID %%p /F >nul 2>nul
    set "ACHOU=1"
)
if defined ACHOU (
    echo   IOC Check encerrado.
) else (
    echo   O IOC Check nao estava em execucao.
)
ping -n 3 127.0.0.1 >nul
exit /b 0
