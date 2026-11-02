#!/usr/bin/env sh
# Prueft die Eigenschaften, auf denen das Konstrukt beruht.
# Voraussetzung: docker compose up -d --build ist gelaufen.
set -u

cd "$(dirname "$0")/.."

URL="http://${EDGE_BIND:-127.0.0.1}:${EDGE_PORT:-8888}"
fails=0

ok()   { printf '  OK    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; fails=$((fails+1)); }

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

echo "5) Gateway hat KEINEN Weg ins Internet"
if docker compose exec -T gateway python -c "
import socket,sys
socket.setdefaulttimeout(5)
try:
    socket.create_connection(('1.1.1.1', 443))
except Exception:
    sys.exit(0)
sys.exit(1)
" >/dev/null 2>&1; then
    ok "Gateway kommt nicht raus"
else
    fail "Gateway erreicht das Internet - Netztrennung ist kaputt"
fi

echo "6) SearXNG kommt nur ueber den WebProxy raus"
if docker compose exec -T searxng sh -c \
   "wget --no-proxy -q -T 5 -O /dev/null https://example.com" >/dev/null 2>&1; then
    fail "SearXNG erreicht das Internet direkt - Proxy ist umgehbar"
else
    ok "SearXNG hat ohne Proxy keine Route"
fi

echo
if [ "$fails" -eq 0 ]; then
    echo "alles gruen"
else
    echo "$fails Pruefung(en) fehlgeschlagen"
fi
exit "$fails"
