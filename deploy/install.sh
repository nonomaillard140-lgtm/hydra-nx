#!/bin/sh
set -eu

DRY_RUN=0
DOMAIN=""
BINARY="$(pwd)/nx"
PREFIX="/opt/hydra"
DATA="/var/lib/hydra"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --domain) DOMAIN="${2:-}"; shift ;;
        --binary) BINARY="${2:-}"; shift ;;
        --prefix) PREFIX="${2:-}"; shift ;;
        --data) DATA="${2:-}"; shift ;;
        *) echo "Option inconnue: $1" >&2; exit 2 ;;
    esac
    shift
done

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] %s\n' "$*"
    else
        "$@"
    fi
}

if [ -r /etc/os-release ]; then
    . /etc/os-release
    printf 'Distribution détectée: %s %s\n' "${ID:-inconnue}" "${VERSION_ID:-inconnue}"
    if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "12" ]; then
        echo "Avertissement: la procédure est validée pour Debian 12." >&2
    fi
fi
if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    echo "Exécutez ce script en root, ou utilisez --dry-run." >&2
    exit 1
fi
if [ ! -f "$BINARY" ]; then
    echo "Binaire introuvable: $BINARY (compilez avec make build ou passez --binary)." >&2
    exit 1
fi

run id hydra >/dev/null 2>&1 || run useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin hydra
run install -d -o root -g root -m 0755 "$PREFIX"
run install -d -o hydra -g hydra -m 0750 "$DATA" "$DATA/public" "$DATA/public/lists"
run install -o root -g root -m 0755 "$BINARY" "$PREFIX/nx"
run install -m 0644 "$(dirname "$0")/hydra.service" /etc/systemd/system/hydra.service
run systemctl daemon-reload
run systemctl enable hydra
run systemctl restart hydra

if [ -n "$DOMAIN" ]; then
    if ! command -v caddy >/dev/null 2>&1; then
        run apt-get update
        run apt-get install -y caddy
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] Caddy: %s reverse_proxy 127.0.0.1:8080\n' "$DOMAIN"
    else
        printf '%s {\n    encode zstd gzip\n    reverse_proxy 127.0.0.1:8080\n}\n' "$DOMAIN" > /etc/caddy/Caddyfile
        caddy validate --config /etc/caddy/Caddyfile
        systemctl enable caddy
        systemctl restart caddy
    fi
fi

if [ "$DRY_RUN" -eq 0 ]; then
    sleep 2
    systemctl --no-pager --full status hydra || true
    echo "Identifiants initiaux, uniquement présents lors du tout premier démarrage:"
    journalctl -u hydra --since "-2 min" --no-pager | sed -n '/Compte administrateur initial/,+3p'
    if [ -n "$DOMAIN" ]; then
        echo "Console: https://$DOMAIN/login"
    else
        echo "Console locale: http://127.0.0.1:8080/login (configurez Caddy pour HTTPS)."
    fi
else
    echo "Simulation terminée, aucune modification appliquée."
fi
