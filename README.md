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

## Telemetrie an aimonitor

Standardmäßig **aus**. Leere `AIMON_URL` heißt: kein Worker, kein Versand,
der Proxy läuft unverändert.

```
AIMON_URL=http://aimon.lan:8420/api/v1/ingest/privacy
AIMON_TOKEN=<Token mit Scope ingest>
AIMON_NODE=proxy-host-01
```

Selbsttest (sendet mit `dry_run=1`, verfälscht also keine Zähler):

```bash
make aimon-test
```

### Was gesendet wird

Alle 10 Sekunden ein Snapshot der kumulativen Zähler plus die seitdem
angefallenen Eingriffe. Durchgelassene Anfragen **nicht** einzeln — dafür
sind die Zähler da.

Die Zähler sind kumulativ seit Prozessstart, nie Deltas. aimonitor bildet
Raten selbst und erkennt einen Neustart am Rücksprung. Nebeneffekt: ein
Ausfall des Monitorings verliert keine Zahlen, der nächste erfolgreiche
Snapshot enthält sie wieder.

### Was nicht gesendet wird

| Feld | Status | Grund |
|---|---|---|
| `query_raw` | aus (`AIMON_SEND_RAW_QUERIES`) | Hebelt den Zweck des Projekts aus |
| `query_redacted` | **aus** (`AIMON_SEND_REDACTED_QUERIES`) | siehe unten |
| `client_id` | **wird nicht gebaut** | kein Session-Schlüssel vorhanden |
| Treffertext in `matched_spans` | nie | nur Offsets und Typ |

**Warum `query_redacted` standardmäßig aus ist.** Die geschwärzte Fassung
entsteht in `filterd/pii/policy.py:redact()`, indem jede *erkannte*
Fundstelle durch `<TYP>` ersetzt wird — keine Sterne, keine Teilmaskierung,
die Länge wird nicht verraten. Das Verfahren ist sauber. Die Erkennung ist
es nicht: NER arbeitet probabilistisch und lässt bei kurzen,
kleingeschriebenen Suchanfragen Namen durch. Eine Anfrage mit zwei Namen,
von denen einer erkannt wird, ist nach dem Ersetzen immer noch
personenbezogen. Diese Garantie kann der Filter nicht geben, also bleibt das
Feld weg. Was bleibt, reicht für ein Dashboard: `category`, `rule`,
`query_sha256`, `query_len`, `matched_spans`.

Wer es trotzdem will, setzt `AIMON_SEND_REDACTED_QUERIES=true` und
akzeptiert damit Personenbezug im Dashboard.

**Warum es kein `client_id` gibt.** Ein Pseudonym bräuchte eine Session-ID,
die mit einem nur im Proxy liegenden Schlüssel gehasht wird. OpenWebUI
schickt keine. Bliebe die IP-Adresse — die wäre kein Pseudonym, sondern
genau das, was nirgends auftauchen soll. Also kein Feld.

**`query_sha256`** ist der Hash der *Original*anfrage, damit aimonitor
wiederkehrende Anfragen erkennt, ohne sie zu kennen. Ehrlich dazu: eine
kurze Suchanfrage ist durchprobierbar, das ist ein
Wiedererkennungsmerkmal und keine Anonymisierung. `AIMON_QUERY_HASH_SALT`
schließt das, macht Hashes zwischen zwei Installationen aber
unvergleichbar. `AIMON_SEND_QUERY_HASH=false` lässt das Feld weg.

### Woher `rule` kommt

Das Feld unterscheidet einen zu scharfen Filter von echten Personensuchen.
Jeder Treffer trägt seine Herkunft:

| Quelle | `source` | `rule` |
|---|---|---|
| spaCy-NER | `ner` | `presidio.spacy` |
| Presidio-Muster | `pattern` | `presidio.email`, `presidio.iban`, … |
| eigene Regex-Regeln | `pattern` | `regex.de.de_license_plate`, … |
| Denylist | `denylist` | `denylist.relational_person`, … |

`confidence` wird nur bei `source: ner` gesendet. Der Score einer Regex ist
auf 1.0 gesetzt und wäre als Sicherheitsaussage gelogen.

### Zähler-Identität

`allowed + blocked + redacted + errors = requests` — exakt, nicht ungefähr.
Jede Anfrage landet in genau einem Kübel, bestimmt durch die
Filter-Entscheidung.

`upstream_errors_total` ist bewusst **nicht** Teil dieser Summe. Ein Fehler
von SearXNG trifft eine Anfrage, die der Filter bereits durchgelassen hat —
sie zählt als `allowed` (oder `redacted`) und zusätzlich als
Upstream-Fehler. Das ist eine zweite Dimension, kein vierter Kübel.
Andernfalls wäre dieselbe Anfrage doppelt gezählt.

`errors_total` zählt nur, was der Proxy selbst nicht verarbeiten konnte:
Filter nicht erreichbar (`filter.unavailable`) und zu lange Anfragen
(`gateway.max_query_len`). Letzteres ist streng genommen eine Ablehnung,
kein Fehler — es muss aber in einen der vier Kübel, sonst stimmt die
Identität nicht.

### Verhalten bei Ausfall

Entscheidungen gehen in eine begrenzte Warteschlange (5000), ein eigener
Worker sendet. Der Request-Pfad wartet nie auf HTTP und sieht keine
Telemetrie-Fehler.

Fällt aimonitor aus: Timeout nach 5 s, Backoff 1 → 60 s mit Jitter, der
Batch bleibt liegen und wird erneut versucht. Läuft die Warteschlange über,
fallen die **ältesten** Einträge raus und `dropped_total` zählt mit — dieser
Zähler sagt dir, dass du Einzelmeldungen verpasst hast. Die kumulativen
Zähler selbst gehen dabei nie verloren.

Nach zehn Minuten Ausfall: die Zähler sind vollständig, von den Einzel-
meldungen die letzten 5000. `4xx` außer `429` wird nicht wiederholt — ein
falsches Token heilt kein Wiederholen; der Batch wird verworfen und einmal
geloggt.

`/healthz` zeigt den Zustand:

```json
{"telemetry": {"enabled": true, "queued": 12, "backoff_s": 0.0, "last_error": null, "dropped_total": 0}}
```

## Tests

```bash
make test
```

95 Unit-Tests auf Policy-Auswertung, deutsche Erkenner, Schwärzung,
Cache-Schlüssel, Log-Modi und Telemetrie. Laufen ohne Docker und ohne NLP-Modelle, weil
`filterd/pii/policy.py` und `filterd/pii/recognizers_de.py` bewusst frei
von Presidio-Importen sind.

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
  telemetry.py              Zähler, Warteschlange, Versand an aimonitor
  categories.py             Erkenner-Typ -> Monitoring-Kategorie
  __main__.py               CLI: --aimon-test
filterd/pii/
  policy.py                 Policy-Auswertung (ohne Presidio, testbar)
  engine.py                 Presidio + spaCy
  recognizers_de.py         deutsche Regex-Erkenner (getrennt von Presidio)
config/policy.yml           Filterregeln
config/searxng/             SearXNG-Konfiguration (Template)
config/tinyproxy/           Egress-Proxy
scripts/init.sh             Erstkonfiguration
scripts/verify.sh           Integrationsprüfung
```
