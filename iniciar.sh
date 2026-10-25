#!/usr/bin/env sh
# IOC Check - inicialização com um comando (Linux e macOS)
#   1. confere o Python
#   2. cria o ambiente virtual e instala as dependências (só na 1ª vez)
#   3. inicia o servidor em segundo plano e abre o navegador em http://localhost:5000
#      (para encerrar: botão "Encerrar" (barra lateral) no app)
set -e
cd "$(dirname "$0")"

PORTA=5000
ENDERECO="http://localhost:$PORTA"
PY_VENV=".venv/bin/python"

abrir_navegador() {
    if command -v xdg-open >/dev/null 2>&1; then xdg-open "$ENDERECO" >/dev/null 2>&1
    elif command -v open >/dev/null 2>&1; then open "$ENDERECO"
    fi
}

# Uma .venv copiada de outro computador não funciona aqui: recria
if [ -x "$PY_VENV" ] && ! "$PY_VENV" -c "import sys" >/dev/null 2>&1; then
    echo "[1/3] Ambiente virtual de outro computador ou corrompido: recriando ..."
    rm -rf .venv
fi

if [ ! -x "$PY_VENV" ]; then
    if ! command -v python3 >/dev/null 2>&1; then
        echo "[ERRO] Python 3 não encontrado. Instale o Python 3.10 ou superior."
        exit 1
    fi
    echo "[1/3] Criando o ambiente virtual .venv ..."
    python3 -m venv .venv
else
    echo "[1/3] Ambiente virtual encontrado."
fi

# Testa os módulos de verdade, inclusive a parte compilada do Pillow (_imaging)
CHECK="import flask, flask_sqlalchemy, sqlalchemy, requests, dotenv, playwright; from PIL import Image, ImageDraw, ImageFont; Image.new('RGB', (1, 1))"
if "$PY_VENV" -c "$CHECK" >/dev/null 2>&1; then
    echo "[2/3] Dependências já instaladas."
else
    echo "[2/3] Instalando as dependências ..."
    "$PY_VENV" -m pip install --disable-pip-version-check --prefer-binary -q -r backend/requirements.txt
    if ! "$PY_VENV" -c "$CHECK" >/dev/null 2>&1; then
        echo "      Instalação incompleta detectada: reinstalando do zero ..."
        "$PY_VENV" -m pip install --disable-pip-version-check --prefer-binary --force-reinstall --no-cache-dir -q -r backend/requirements.txt
        "$PY_VENV" -c "$CHECK" || { echo "[ERRO] Dependências não instaladas. Apague a pasta .venv e tente de novo."; exit 1; }
    fi
fi

# Navegador para o "Print da página": usa Chrome/Edge instalados; se não houver, baixa o Chromium
if ! command -v google-chrome >/dev/null 2>&1 && ! command -v microsoft-edge >/dev/null 2>&1    && [ ! -d "/Applications/Google Chrome.app" ] && [ ! -f ".venv/.chromium_ok" ]; then
    echo "      Baixando o navegador usado nos prints (só na primeira vez) ..."
    "$PY_VENV" -m playwright install chromium && touch .venv/.chromium_ok
fi

echo "[3/3] Iniciando o IOC Check em segundo plano ..."
mkdir -p backend/instance
FLASK_DEBUG=0 PORT=$PORTA nohup "$PY_VENV" backend/run.py >> backend/instance/ioc_check.log 2>&1 &

# Espera o servidor responder (até ~40 segundos)
tentativas=0
until "$PY_VENV" -c "import socket; socket.create_connection(('127.0.0.1', $PORTA), 1)" 2>/dev/null; do
    tentativas=$((tentativas + 1))
    if [ "$tentativas" -ge 40 ]; then
        echo "[ERRO] O servidor não respondeu. Últimas mensagens:"
        tail -n 15 backend/instance/ioc_check.log
        exit 1
    fi
    sleep 1
done

echo "IOC Check rodando em $ENDERECO (em segundo plano)."
echo "Para encerrar, use o botão \"Encerrar\" (barra lateral) no app."
abrir_navegador
