#!/usr/bin/env sh
# Zeigt, wie der Filter eine Anfrage bewertet - ohne zu suchen.
# Aufruf: sh scripts/probe.sh "<suchanfrage>" [de|en]
set -u

cd "$(dirname "$0")/.."

if [ $# -lt 1 ]; then
    echo "Aufruf: sh scripts/probe.sh \"<suchanfrage>\" [de|en]" >&2
    exit 2
fi

q="$1"
lang="${2:-de}"

DOCKER="docker"
docker compose ps >/dev/null 2>&1 || DOCKER="sudo docker"

$DOCKER compose exec -T filter python -c '
import json, sys, urllib.request

payload = json.dumps({"text": sys.argv[1], "language": sys.argv[2]}).encode()
req = urllib.request.Request(
    "http://localhost:8001/analyze",
    data=payload,
    headers={"Content-Type": "application/json"},
)
d = json.loads(urllib.request.urlopen(req, timeout=30).read())

print("Anfrage:     %s" % sys.argv[1])
print("Aktion:      %s" % d["action"])
print("Blockiert:   %s" % (", ".join(d["blocking_types"]) or "-"))
print("Geschwaerzt: %s" % d["redacted_text"])
if d["findings"]:
    print("Fundstellen:")
    for f in d["findings"]:
        print("  %-22s score %.2f  pos %d-%d"
              % (f["type"], f["score"], f["start"], f["end"]))
else:
    print("Fundstellen: keine")
' "$q" "$lang"
