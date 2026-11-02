# SearXNG Privacy Proxy

Vorgeschalteter Datenschutzfilter für Websuche aus einem lokalen LLM heraus.
OpenWebUI spricht ihn wie eine normale SearXNG-Instanz an; Anfragen mit
Personenbezug erreichen das Internet nicht.

## Aufbau

```
                    ┌─────────────────────────────────────────────┐
  OpenWebUI ──────► │ edge (nginx)        Netz: edge + core       │
  (lokales LLM)     │  kein Access-Log, baut nie selbst raus      │
                    └──────────────────┬──────────────────────────┘
                                       │
   ────────────── core (internal: keine Route ins Internet) ───────────────
                                       │
                    ┌──────────────────▼──────────────────┐
                    │ gateway                              │──► LOG (JSON)
                    │  SearXNG-kompatible JSON-API         │    geschwärzt
                    └───┬──────────────┬───────────────┬───┘
                        │              │               │
                ┌───────▼──────┐  ┌────▼────┐   ┌──────▼──────┐
                │ filter       │  │ valkey  │   │ searxng     │
                │ Regex + NER  │  │ Cache   │   │             │
                │ (Presidio)   │  │ (Hash)  │   └──────┬──────┘
                └──────────────┘  └─────────┘          │
                                                ┌──────▼──────┐
                                                │ webproxy    │ Netz: core
                                                │ (tinyproxy) │     + egress
                                                └──────┬──────┘
   ──────────────────────────────────────────────────  │  ───────────────────
                                                       ▼
                                                   Internet
```

Reihenfolge pro Anfrage: **Filter → Cache → SearXNG → WebProxy**.
Geloggt wird erst *nach* dem Filter.

### Warum so und nicht wie im ursprünglichen Entwurf

| Entwurf | Problem | Hier |
|---|---|---|
| Proxy loggt die eingehende Query | ungefiltertes PII landet dauerhaft auf Platte | Log erst nach dem Filter, Default `redacted` |
| nur NER | fängt keine IBAN, Steuer-ID, Kennzeichen, Zugangsdaten | Regex-Erkenner **und** NER |
| alle Entitäten entfernen | Suche wird unbrauchbar, System wird umgangen | Orte/Orgs erlaubt, Personen/Kennungen blockiert |
| WebProxy als vorgesehener Weg | LLM-Tools gehen drumherum | Netztrennung: `core` ist `internal` |
| kein Cache | jede Wiederholung geht erneut raus | Valkey-Cache auf Hash der gefilterten Query |

## Entscheidungen, die hier getroffen wurden

**Blockieren statt stillschweigend schwärzen.** Wird PII erkannt, geht die
Anfrage gar nicht raus. Das Gateway antwortet mit HTTP 200 und *einem*
Pseudo-Treffer, der den Grund nennt — OpenWebUI reicht Treffer an das Modell
weiter, Fehlerstatus dagegen nicht. Das LLM liest die Begründung und kann
selbst allgemeiner neu formulieren. Umschaltbar über
`GATEWAY_BLOCK_RESPONSE` (`inform` | `empty` | `error`).

**Orte und Organisationen sind erlaubt.** Eine Suchanfrage besteht
überwiegend aus Named Entities. „Öffnungszeiten Bürgeramt Pankow" ohne Ort
ist wertlos. Blockiert wird direkter Personenbezug: Namen, Kontaktdaten,
Kennungen, Anschriften. Anpassbar in `config/policy.yml`.

**Fail closed.** Ist der Filter nicht erreichbar, antwortet das Gateway mit
503 und sucht nicht. Keine Suche ist besser als eine ungefilterte.

**Die Trennung wird erzwungen, nicht nur vorgesehen.** `gateway`, `filter`,
`searxng` und `valkey` hängen ausschließlich im Docker-Netz `core`
(`internal: true`) und haben keine Route ins Internet. Der einzige Ausgang
ist `webproxy`. Der Dienst, der die ungefilterte Anfrage sieht, kann sie
technisch nicht verschicken; der Dienst, der ins Internet darf, sieht nur
Gefiltertes. `scripts/verify.sh` prüft genau das nach.

## Start

```bash
sh scripts/init.sh
```

```bash
docker compose up -d --build
```

Der erste Build lädt die spaCy-Modelle (~500 MB), der erste Start des
Filters dauert ein bis zwei Minuten. Danach:

```bash
sh scripts/verify.sh
```

## OpenWebUI anbinden

Admin-Panel → Einstellungen → **Websuche**:

| Feld | Wert |
|---|---|
| Websuche | aktiviert |
| Suchmaschine | `searxng` |
| SearXNG Query URL | `http://127.0.0.1:8888/search?q=<query>` |

Läuft OpenWebUI selbst im Container, ist `127.0.0.1` falsch — dann die
LAN-IP des Hosts eintragen und `EDGE_BIND=0.0.0.0` in der `.env` setzen.
Oder, sauberer, OpenWebUI an das `edge`-Netz dieses Compose-Projekts hängen
und `http://edge:8888/search?q=<query>` verwenden.

**Wichtig:** Aktiviere in OpenWebUI nicht zusätzlich das Abrufen ganzer
Seiteninhalte über einen anderen Weg. Was OpenWebUI selbst direkt lädt,
geht an diesem Stack vorbei. Dieser Proxy kontrolliert, was *er* nach außen
gibt — nicht, was andere Prozesse auf deinem Host tun.

## Konfiguration

`.env` steuert Ports, Logging und Verhalten (siehe `.env.example`).
`config/policy.yml` steuert den Filter:

```yaml
actions:
  PERSON: block        # Anfrage geht nicht raus
  LOCATION: allow      # nötig für brauchbare Treffer
  IBAN_CODE: block
default_action: redact # alles nicht Gelistete wird ersetzt

thresholds:
  PERSON: 0.6          # spaCy wird bei kurzen Anfragen oft falsch positiv

allowlist:             # Begriffe, die NER fälschlich als Person/Org markiert
  - docker
  - debian

denylist:              # deterministisch, unabhängig vom Modell
  - name: RELATIONAL_PERSON
    pattern: "(?i)\\b(mein|meine)\\s+(chef|arzt|anwalt|nachbar)\\b"
```

Nach Änderungen:

```bash
make policy-reload
```

Die Denylist ist der wichtigere Teil. Sie fängt Personenbezug ab, der gar
keine Named Entity ist — „was verdient mein chef", `api_key=…`,
`nas.fritz.box` — und arbeitet deterministisch statt probabilistisch.

## Logging

Default `GATEWAY_LOG_QUERIES=redacted`: geloggt wird die geschwärzte
Fassung, nie die Originalanfrage. Alternativen: `none`, `hashed`, `raw`.
`raw` hebelt den Zweck des Projekts aus und existiert nur zum Debuggen.

Ebenfalls abgeschaltet, weil sie sonst Klartext-Queries schreiben würden:
nginx `access_log`, uvicorn `uvicorn.access`, tinyproxy auf `LogLevel
Warning`. Der Filter loggt nur Typen von Fundstellen, nie deren Inhalt.

Format ist JSON pro Zeile:

```json
{"event":"gateway.blocked","request_id":"a1b2c3","query":"adresse von <PERSON>","blocking_types":["PERSON"],"duration_ms":41.2}
```

## Filterung testen

Einzelne Anfrage bewerten lassen, ohne zu suchen - zeigt Aktion, Fundstellen
mit Score und die geschwaerzte Fassung:

```bash
sh scripts/probe.sh "telefonnummer von thomas berger"
```

Am Gateway vorbei an der Chat-Oberflaeche pruefen (`X-Privacy-Filter` ist
`allow`, `redact`, `blocked` oder `cache`):

```bash
curl -sD- -o /dev/null -G --data-urlencode "q=was verdient mein chef" \
     http://127.0.0.1:8888/search
```

Nicht ueber das LLM testen. Das Modell interpretiert die Blockmeldung auf
eigene Faust und sagt dann Dinge, die der Filter so nicht behauptet.

## Tests

```bash
make test
```

34 Unit-Tests auf Policy-Auswertung, Schwärzung, Ergebnis-Hygiene,
Cache-Schlüssel und Log-Modi. Laufen ohne Docker und ohne NLP-Modelle, weil
`filterd/pii/policy.py` bewusst frei von Presidio-Importen ist.

`make verify` prüft zusätzlich gegen den laufenden Stack, ob die
Netztrennung tatsächlich hält.

## Grenzen

Ehrlich gesagt, damit niemand mehr erwartet als da ist:

- **NER ist probabilistisch.** Bei kurzen, kleingeschriebenen Suchanfragen
  ohne Satzkontext ist die Trefferquote deutlich schlechter als auf
  Fließtext. Es wird Namen durchlassen. Die Regex-Erkenner und die Denylist
  sind der verlässliche Teil, NER der ergänzende.
- **Kein Schutz gegen Rückschluss aus Kontext.** „Chefarzt Kardiologie
  Klinikum X Sprechstunde Donnerstag" enthält keinen Namen und wird
  durchgelassen — identifiziert aber womöglich eine Person.
- **Korrelation bleibt.** Google und Bing sehen eine Folge von Anfragen aus
  derselben Quelle. Der WebProxy verdeckt nur die interne Topologie, nicht
  die IP deines Anschlusses. Für IP-Anonymität gehört hinter `webproxy` ein
  VPN oder Tor.
- **Ergebnis-Bereinigung ist Hygiene, keine Sicherheitsgrenze.**
  `gateway/gw/sanitize.py` entfernt unsichtbare Zeichen und deckelt Längen.
  Gegen Prompt Injection aus Suchergebnissen hilft das nicht wesentlich —
  das ist im Prompt des LLM zu lösen, nicht hier.
- **Der Egress ist nicht default-deny.** `webproxy` lässt jedes Ziel zu.
  `config/tinyproxy/filter` enthält eine Ziel-Allowlist, die in
  `tinyproxy.conf` auskommentiert ist; aktivieren bricht jede Engine, die
  nicht in der Liste steht.
- **Der Stack schützt nur den Weg durch ihn hindurch.** Jedes andere Tool
  deines LLM, das selbst HTTP spricht, geht daran vorbei.

## Struktur

```
docker-compose.yml          Netztrennung und Dienste
edge/nginx.conf             Annahme von OpenWebUI, kein Access-Log
gateway/gw/
  main.py                   Ablauf: Filter -> Cache -> SearXNG
  responses.py              SearXNG-kompatible Antwortformen
  sanitize.py               Ergebnis-Hygiene
  cache.py                  Hash-Schlüssel, Valkey
  logging_setup.py          Log-Modi für Queries
filterd/pii/
  policy.py                 Policy-Auswertung (ohne Presidio, testbar)
  engine.py                 Presidio + spaCy
  recognizers_de.py         deutsche Regex-Erkenner
config/policy.yml           Filterregeln
config/searxng/             SearXNG-Konfiguration (Template)
config/tinyproxy/           Egress-Proxy
scripts/init.sh             Erstkonfiguration
scripts/verify.sh           Integrationsprüfung
```
