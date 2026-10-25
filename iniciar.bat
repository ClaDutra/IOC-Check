@echo off
rem ============================================================
rem  IOC Check - inicializacao com um clique (Windows)
rem  1. confere o Python e o ambiente virtual (.venv)
rem  2. instala ou repara as dependencias (so quando preciso)
rem  3. inicia o servidor EM SEGUNDO PLANO (sem janela do CMD) e abre o
rem     navegador em http://localhost:5000. Esta janela fecha sozinha.
rem  Para encerrar: botao "Encerrar" (barra lateral) no app ou o arquivo parar.bat
rem ============================================================
chcp 65001 >nul
setlocal
title IOC Check
cd /d "%~dp0"

if not defined PORTA set "PORTA=5000"
set "ENDERECO=http://localhost:%PORTA%"
set "PY_VENV=.venv\Scripts\python.exe"
rem Testa os modulos de verdade, inclusive a parte compilada do Pillow (_imaging)
set "CHECK=import flask, flask_sqlalchemy, sqlalchemy, requests, dotenv, playwright; from PIL import Image, ImageDraw, ImageFont; Image.new('RGB', (1, 1))"

echo.
echo   IOC Check - verificador pessoal de indicadores de comprometimento
echo   ----------------------------------------------------------------
echo.

rem Se o app ja estiver rodando, reinicia para carregar a versao mais recente
rem (um servidor aberto antes de uma atualizacao continuaria com o codigo antigo)
set "REINICIOU="
for /f "tokens=5" %%p in ('netstat -ano ^| findstr /r /c:":%PORTA% .*LISTENING"') do (
    taskkill /PID %%p /F >nul 2>nul
    set "REINICIOU=1"
)
if defined REINICIOU (
    echo   O IOC Check ja estava aberto: reiniciando com a versao mais recente ...
    ping -n 3 127.0.0.1 >nul
)

rem Python do computador: comando "python" ou o lancador "py"
set "SYS_PY="
python -c "import sys" >nul 2>nul && set "SYS_PY=python"
if not defined SYS_PY py -3 -c "import sys" >nul 2>nul && set "SYS_PY=py -3"

rem 1) Ambiente virtual: uma .venv copiada de outro computador nao funciona aqui
if exist "%PY_VENV%" goto venv_existe

:criar_venv
if not defined SYS_PY goto sem_python
echo   [1/3] Criando o ambiente virtual .venv ...
rem --clear apaga restos de uma .venv antiga que o rmdir nao conseguiu remover
%SYS_PY% -m venv --clear .venv
if errorlevel 1 goto erro
goto dependencias

:venv_existe
"%PY_VENV%" -c "import sys" >nul 2>nul
if errorlevel 1 (
    echo   [1/3] O ambiente virtual veio de outro computador ou esta corrompido: recriando ...
    rmdir /s /q .venv
    goto criar_venv
)
echo   [1/3] Ambiente virtual encontrado.

rem 2) Dependencias: instala se faltar e repara se a instalacao estiver incompleta
:dependencias
"%PY_VENV%" -c "%CHECK%" >nul 2>nul
if not errorlevel 1 (
    echo   [2/3] Dependencias ja instaladas.
    goto iniciar
)
echo   [2/3] Instalando as dependencias, isso pode levar alguns minutos ...
"%PY_VENV%" -m pip install --disable-pip-version-check --prefer-binary -q -r backend\requirements.txt
"%PY_VENV%" -c "%CHECK%" >nul 2>nul
if not errorlevel 1 goto iniciar
echo         Instalacao incompleta detectada: reinstalando do zero ...
"%PY_VENV%" -m pip install --disable-pip-version-check --prefer-binary --force-reinstall --no-cache-dir -q -r backend\requirements.txt
"%PY_VENV%" -c "%CHECK%"
if errorlevel 1 goto erro_dependencias

rem 3) Inicia o servidor em segundo plano: pythonw roda sem abrir janela
:iniciar
set "FLASK_DEBUG=0"
set "PORT=%PORTA%"
set "PY_FUNDO=.venv\Scripts\pythonw.exe"
if not exist "%PY_FUNDO%" set "PY_FUNDO=%PY_VENV%"
echo   [3/3] Iniciando o IOC Check em segundo plano ...
start "" "%PY_FUNDO%" backend\run.py

rem Espera o servidor responder (ate ~40 segundos)
set /a TENTATIVAS=0
:aguardar
ping -n 2 127.0.0.1 >nul
netstat -ano | findstr /r /c:":%PORTA% .*LISTENING" >nul 2>nul
if %errorlevel%==0 goto pronto
set /a TENTATIVAS+=1
if %TENTATIVAS% lss 20 goto aguardar
goto erro_servidor

:pronto
echo.
echo   IOC Check rodando em %ENDERECO%
echo   Esta janela vai fechar; o app continua funcionando em segundo plano.
echo   Para encerrar, use o botao "Encerrar" (barra lateral) no app ou o parar.bat.
if not defined IOC_SEM_NAVEGADOR start "" "%ENDERECO%"
ping -n 4 127.0.0.1 >nul
exit /b 0

:erro_servidor
echo.
echo   [ERRO] O servidor nao respondeu. Ultimas mensagens do registro:
echo.
if exist "backend\instance\ioc_check.log" powershell -NoProfile -Command "Get-Content -Tail 15 'backend\instance\ioc_check.log'"
echo.
echo   Se precisar, apague a pasta .venv e execute este arquivo novamente.
echo.
pause
exit /b 1

:sem_python
echo   [ERRO] Python nao encontrado.
echo   Instale o Python 3.10 ou superior, 64 bits, em https://www.python.org/downloads/
echo   e marque a opcao "Add Python to PATH" durante a instalacao.
echo.
pause
exit /b 1

:erro_dependencias
echo.
echo   [ERRO] Nao foi possivel instalar as dependencias neste Python:
"%PY_VENV%" -c "import sys, platform; print('         Python', sys.version.split()[0], '-', platform.architecture()[0])"
echo   Instale o Python 64 bits, versao 3.10 a 3.14, em https://www.python.org/downloads/
echo   marcando "Add Python to PATH". Depois apague a pasta .venv e execute este arquivo de novo.
echo.
pause
exit /b 1

:erro
echo.
echo   [ERRO] Algo deu errado. Leia as mensagens acima.
echo   Se precisar, apague a pasta .venv e execute este arquivo novamente.
echo.
pause
exit /b 1
