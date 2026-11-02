"""Gateway-Logik: Antwortformen, Ergebnis-Hygiene, Cache-Schluessel, Logging."""

from gw.cache import cache_key
from gw.logging_setup import query_for_log
from gw.responses import block_message, block_response, empty_response
from gw.sanitize import clean_text, clean_url, sanitize_results


# --- Blockier-Antwort -----------------------------------------------------

def test_block_inform_liefert_begruendung_als_treffer():
    """OpenWebUI reicht Treffer ans Modell weiter, Fehlerstatus nicht."""
    r = block_response("Adresse von <PERSON>", ["PERSON"], "inform")
    assert r["number_of_results"] == 1
    assert r["results"][0]["engine"] == "privacy-filter"
    assert "Personenname" in r["results"][0]["content"]
    assert "blockiert" in r["results"][0]["content"].lower()


def test_block_empty_liefert_nichts():
    r = block_response("<PERSON>", ["PERSON"], "empty")
    assert r["results"] == []
    assert r["number_of_results"] == 0


def test_block_antwort_enthaelt_nur_geschwaerzte_query():
    r = block_response("Adresse von <PERSON>", ["PERSON"], "inform")
    assert r["query"] == "Adresse von <PERSON>"


def test_block_message_faellt_auf_default_zurueck():
    assert "personenbezogene Daten" in block_message([])


def test_unbekannter_typ_wird_durchgereicht():
    assert "WAS_AUCH_IMMER" in block_message(["WAS_AUCH_IMMER"])


# --- Ergebnis-Hygiene -----------------------------------------------------

def test_unsichtbare_zeichen_werden_entfernt():
    assert clean_text("Hallo​Welt‮!", 100) == "HalloWelt!"


def test_laenge_wird_gedeckelt():
    out = clean_text("x" * 500, 50)
    assert len(out) <= 56 and out.endswith("[…]")


def test_nur_http_urls():
    assert clean_url("https://example.com/a") == "https://example.com/a"
    assert clean_url("javascript:alert(1)") == ""
    assert clean_url("file:///etc/passwd") == ""
    assert clean_url(None) == ""


def test_sanitize_wirft_treffer_ohne_gueltige_url_weg():
    payload = {
        "query": "test",
        "results": [
            {"url": "https://a.example/1", "title": "A", "content": "x"},
            {"url": "javascript:void(0)", "title": "B", "content": "y"},
            {"not": "a dict"},
        ],
    }
    out = sanitize_results(payload, 20, 2000)
    assert out["number_of_results"] == 1
    assert out["results"][0]["url"] == "https://a.example/1"


def test_sanitize_respektiert_max_results():
    payload = {"query": "t", "results": [
        {"url": f"https://e.example/{i}", "title": "t", "content": "c"} for i in range(50)
    ]}
    assert sanitize_results(payload, 5, 2000)["number_of_results"] == 5


def test_sanitize_vertraegt_leere_antwort():
    out = sanitize_results({}, 20, 2000)
    assert out["results"] == [] and out["number_of_results"] == 0


# --- Cache ----------------------------------------------------------------

def test_cache_key_ignoriert_leere_parameter():
    a = cache_key("wetter berlin", {"language": "de", "pageno": None, "engines": ""})
    b = cache_key("wetter berlin", {"language": "de"})
    assert a == b


def test_cache_key_unterscheidet_queries():
    assert cache_key("a", {}) != cache_key("b", {})


def test_cache_key_enthaelt_keinen_klartext():
    key = cache_key("mein geheimer suchbegriff", {})
    assert "geheim" not in key and key.startswith("q:")


# --- Logging --------------------------------------------------------------

def test_log_mode_none():
    assert query_for_log("roh", "<X>", "none") is None


def test_log_mode_redacted_ist_default():
    assert query_for_log("mail an max@a.de", "mail an <EMAIL_ADDRESS>", "redacted") == (
        "mail an <EMAIL_ADDRESS>"
    )
    assert query_for_log("roh", "<X>", "unbekannt") == "<X>"


def test_log_mode_hashed_gibt_keinen_klartext():
    out = query_for_log("max@a.de", "<EMAIL_ADDRESS>", "hashed")
    assert out.startswith("sha256:") and "max" not in out


def test_log_mode_raw_ist_wirklich_raw():
    assert query_for_log("max@a.de", "<E>", "raw") == "max@a.de"
