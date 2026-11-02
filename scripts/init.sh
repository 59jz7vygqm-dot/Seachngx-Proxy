#!/usr/bin/env sh
# Einmalige Vorbereitung: .env und SearXNG-settings.yml erzeugen.
set -eu

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
    cp .env.example .env
    secret="$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    # BSD- und GNU-sed-kompatibel
    sed "s|^SEARXNG_SECRET=.*|SEARXNG_SECRET=${secret}|" .env > .env.tmp && mv .env.tmp .env
    echo "angelegt: .env (SEARXNG_SECRET erzeugt)"
else
    echo "vorhanden: .env - unveraendert"
fi

if [ ! -f config/searxng/settings.yml ]; then
    cp config/searxng/settings.yml.template config/searxng/settings.yml
    echo "angelegt: config/searxng/settings.yml"
else
    echo "vorhanden: config/searxng/settings.yml - unveraendert"
fi

echo
echo "Naechster Schritt: docker compose up -d --build"
