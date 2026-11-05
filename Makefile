.PHONY: init up down build logs test verify probe aimon-test policy-reload clean

init:          ## .env und SearXNG-settings.yml anlegen
	@sh scripts/init.sh

build:
	docker compose build

up: ## Stack starten (Filter braucht beim ersten Start ~1-2 min fuer die Modelle)
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f gateway filter

test:          ## Unit-Tests (ohne Docker, ohne NLP-Modelle)
	python3 -m pytest tests/ -q

verify:        ## Integrationspruefung gegen den laufenden Stack
	@sh scripts/verify.sh

aimon-test:    ## Beispiel-Payload an aimonitor senden (dry_run)
	@sh scripts/aimon-test.sh

aimon-test-live: ## dasselbe, aber ohne dry_run
	@sh scripts/aimon-test.sh --live

policy-reload: ## config/policy.yml neu einlesen, ohne Modell-Neustart
	docker compose exec gateway python -c "\
import urllib.request;\
print(urllib.request.urlopen(urllib.request.Request('http://filter:8001/reload',method='POST'),timeout=10).read().decode())"

clean:
	docker compose down -v
