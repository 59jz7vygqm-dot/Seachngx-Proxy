#!/usr/bin/env sh
# Prueft die Eigenschaften, auf denen das Konstrukt beruht.
# Voraussetzung: docker compose up -d --build ist gelaufen.
set -u

cd "$(dirname "$0")/.."

# Werte aus der .env uebernehmen, sofern nicht schon in der Umgebung.
# Sonst sucht das Skript auf 127.0.0.1, waehrend der Port z. B. auf der
# Docker-Bridge 172.17.0.1 liegt.
env_get() { [ -f .env ] && sed -n "s/^$1=//p" .env | tail -1; }
EDGE_BIND="${EDGE_BIND:-$(env_get EDGE_BIND)}"
EDGE_PORT="${EDGE_PORT:-$(env_get EDGE_PORT)}"

# 0.0.0.0 heisst "alle Interfaces" und ist keine Zieladresse.
[ "$EDGE_BIND" = "0.0.0.0" ] && EDGE_BIND=127.0.0.1

URL="http://${EDGE_BIND:-127.0.0.1}:${EDGE_PORT:-8888}"
fails=0

ok()   { printf '  OK    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; fails=$((fails+1)); }
skip() { printf '  SKIP  %s\n' "$1"; }
note() { printf '  HINW  %s\n' "$1"; }

# Telemetrie an aimonitor braucht Netzzugang fuer den Gateway. Ist sie
# eingeschaltet, ist Pruefung 5 bewusst aufgehoben - das wird gemeldet,
# nicht verschwiegen.
AIMON_ON=no
if [ -f .env ] && grep -qE '^AIMON_URL=.+' .env; then
    AIMON_ON=yes
fi

# Die Netzpruefungen brauchen Zugriff auf den Docker-Socket. Ohne ihn wird
# NICHT stillschweigend "bestanden" gemeldet, sondern uebersprungen.
DOCKER=""
if docker compose ps >/dev/null 2>&1; then
    DOCKER="docker"
elif sudo docker compose ps >/dev/null 2>&1; then
    DOCKER="sudo docker"
fi

# Fuehrt ein Kommando im Container aus und gibt dessen Ausgabe zurueck.
# Leere Ausgabe = Pruefung nicht ausfuehrbar, nicht "bestanden".
in_container() {
    svc="$1"; shift
    $DOCKER compose exec -T "$svc" "$@" 2>/dev/null
}

echo "1) Health"
if curl -fsS "$URL/healthz" | grep -q '"status":"ok"'; then
    ok "Gateway antwortet"
else
    fail "Gateway antwortet nicht - Rest ist sinnlos"
    exit 1
fi

echo "2) Unverfaengliche Anfrage geht durch"
n=$(curl -fsS --get --data-urlencode "q=aktuelle debian version" "$URL/search" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["number_of_results"])' 2>/dev/null)
case "$n" in
    ''|0) fail "keine Treffer (Engines oder Egress kaputt?)" ;;
    *)    ok "$n Treffer" ;;
esac

echo "3) Anfrage mit PII wird blockiert"
hdr=$(curl -fsS -D- -o /dev/null --get \
      --data-urlencode "q=telefonnummer von thomas berger 0171 2345678" "$URL/search" \
      | tr -d '\r' | grep -i '^x-privacy-filter:')
case "$hdr" in
    *blocked*) ok "blockiert ($hdr)" ;;
    *)         fail "NICHT blockiert ($hdr)" ;;
esac

echo "4) Denylist greift ohne NER"
hdr=$(curl -fsS -D- -o /dev/null --get \
      --data-urlencode "q=was verdient mein chef" "$URL/search" \
      | tr -d '\r' | grep -i '^x-privacy-filter:')
case "$hdr" in
    *blocked*) ok "blockiert" ;;
    *)         fail "NICHT blockiert ($hdr)" ;;
esac

if [ -z "$DOCKER" ]; then
    echo "5) Netzzugang des Gateways"
    skip "kein Zugriff auf den Docker-Socket"
    echo "6) SearXNG kommt nur ueber den WebProxy raus"
    skip "kein Zugriff auf den Docker-Socket"
    echo
    echo "Netzpruefungen uebersprungen. Erneut mit: sudo sh scripts/verify.sh"
else
    # Der Container druckt OPEN oder CLOSED. Alles andere bedeutet, dass die
    # Pruefung nicht lief - das wird als FAIL gewertet, nicht als Erfolg.
    echo "5) Netzzugang des Gateways"
    out=$(in_container gateway python -c "
import socket
socket.setdefaulttimeout(5)
try:
    socket.create_connection(('1.1.1.1', 443)).close()
    print('OPEN')
except Exception:
    print('CLOSED')
")
    case "$out$AIMON_ON" in
        *CLOSED*) ok "Gateway kommt nicht raus" ;;
        *OPEN*yes)
            note "Gateway erreicht das Internet - gewollt, weil Telemetrie an"
            note "      ist. Der Dienst, der die UNGEFILTERTE Anfrage sieht, hat"
            note "      damit vollen Netzzugang. Zum Zurueckdrehen: AIMON_URL"
            note "      leeren und 'egress' beim Gateway aus der compose nehmen."
            ;;
        *OPEN*)   fail "Gateway erreicht das Internet - Netztrennung ist kaputt" ;;
        *)        fail "Pruefung nicht ausfuehrbar (Ausgabe: '$out')" ;;
    esac

    echo "6) SearXNG kommt nur ueber den WebProxy raus"
    out=$(in_container searxng sh -c \
        "wget --no-proxy -q -T 5 -O /dev/null https://1.1.1.1 && echo OPEN || echo CLOSED")
    case "$out" in
        *CLOSED*) ok "SearXNG hat ohne Proxy keine Route" ;;
        *OPEN*)   fail "SearXNG erreicht das Internet direkt - Proxy ist umgehbar" ;;
        *)        fail "Pruefung nicht ausfuehrbar (Ausgabe: '$out')" ;;
    esac
fi

echo
if [ "$fails" -eq 0 ]; then
    echo "alles gruen"
else
    echo "$fails Pruefung(en) fehlgeschlagen"
fi
exit "$fails"
