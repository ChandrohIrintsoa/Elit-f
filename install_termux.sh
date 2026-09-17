#!/data/data/com.termux/files/usr/bin/bash
# Installe le lanceur 'Elit-f' dans Termux : après exécution, tapez
# simplement 'Elit-f' dans un terminal pour lancer l'outil.
set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
        echo "Python introuvable. Installez-le d'abord:  pkg install python" >&2
        exit 1
fi

exec python3 "$SCRIPT_DIR/elitf.py" --install-launcher
