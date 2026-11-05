"""Versandverhalten: Ausfall, Backoff, 4xx, Wiederanlauf.

Beantwortet die Frage "was passiert, wenn aimonitor zehn Minuten weg ist".
"""

import pytest

httpx = pytest.importorskip("httpx", reason="nur fuer die Versand-Tests noetig")

from test_telemetry import FakeSettings, blocked_decision  # noqa: E402

from gw.telemetry import ACTION_BLOCKED, Telemetry  # noqa: E402

RAW = "wohnort von Thomas Berger"


class StubClient:
    """Ersetzt httpx.AsyncClient. Spielt eine Liste von Ergebnissen ab."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.sent: list[dict] = []

    async def post(self, url, json=None, headers=None):
        self.sent.append(json)
        outcome = self.outcomes.pop(0) if self.outcomes else 200
        if isinstance(outcome, Exception):
            raise outcome
        return httpx.Response(outcome, text="", request=httpx.Request("POST", url))

    async def aclose(self):
        pass


def armed(outcomes, **kw) -> tuple[Telemetry, StubClient]:
    t = Telemetry(FakeSettings(**kw))
    client = StubClient(outcomes)
    t._client = client
    return t, client


def fill(t: Telemetry, n: int) -> None:
    for i in range(n):
        t.record(ACTION_BLOCKED, query=f"{RAW} {i}", decision=blocked_decision())


@pytest.mark.asyncio
async def test_erfolgreicher_versand_leert_die_queue():
    t, client = armed([200])
    fill(t, 3)
    await t.flush()
    assert len(client.sent) == 1
    assert len(client.sent[0]["decisions"]) == 3
    assert t._pending == []
    assert t._backoff == 0.0


@pytest.mark.asyncio
async def test_ausfall_haelt_entscheidungen_und_erhoeht_backoff():
    err = httpx.ConnectError("keine Verbindung")
    t, _ = armed([err, err, err])
    fill(t, 2)

    await t.flush()
    assert len(t._pending) == 2
    erster = t._backoff
    assert 0.8 <= erster <= 1.2

    await t.flush()
    assert t._backoff > erster
    assert len(t._pending) == 2


@pytest.mark.asyncio
async def test_backoff_bleibt_unter_60s():
    err = httpx.ConnectError("weg")
    t, _ = armed([err] * 20)
    for _ in range(20):
        await t.flush()
    assert t._backoff <= 60.0 * 1.2


@pytest.mark.asyncio
async def test_zaehler_ueberleben_den_ausfall():
    """Kumulative Zaehler gehen nicht verloren - sie werden neu geschickt."""
    err = httpx.ConnectError("weg")
    t, client = armed([err, 200])
    fill(t, 2)
    await t.flush()
    fill(t, 3)
    await t.flush()
    letzte = client.sent[-1]
    assert letzte["counters"]["blocked_total"] == 5
    assert len(letzte["decisions"]) == 5


@pytest.mark.asyncio
async def test_wiederanlauf_setzt_backoff_zurueck():
    t, _ = armed([httpx.ConnectError("weg"), 200])
    fill(t, 1)
    await t.flush()
    assert t._backoff > 0
    await t.flush()
    assert t._backoff == 0.0
    assert t._last_error is None


@pytest.mark.asyncio
async def test_4xx_wird_nicht_wiederholt():
    """Falsches Token heilt kein Wiederholen. Batch verwerfen, einmal loggen."""
    t, client = armed([401, 200])
    fill(t, 3)
    await t.flush()
    assert t._pending == []
    assert t.counters.dropped_total == 3
    assert t._backoff == 0.0

    fill(t, 1)
    await t.flush()
    assert len(client.sent[-1]["decisions"]) == 1


@pytest.mark.asyncio
async def test_429_wird_wiederholt():
    t, _ = armed([429])
    fill(t, 2)
    await t.flush()
    assert len(t._pending) == 2
    assert t._backoff > 0


@pytest.mark.asyncio
async def test_5xx_wird_wiederholt():
    t, _ = armed([503])
    fill(t, 2)
    await t.flush()
    assert len(t._pending) == 2


@pytest.mark.asyncio
async def test_langer_ausfall_verwirft_aelteste_nicht_neueste():
    """Bei anhaltendem Ausfall darf der Puffer nicht unbegrenzt wachsen."""
    err = httpx.ConnectError("weg")
    t, _ = armed([err] * 10, aimon_queue_max=5, aimon_batch_max=5)
    for runde in range(5):
        fill(t, 4)
        await t.flush()
    assert len(t._pending) <= 5
    assert t.counters.dropped_total > 0
    # Die Zaehler selbst sind davon unberuehrt.
    assert t.counters.blocked_total == 20


@pytest.mark.asyncio
async def test_abgeschaltete_telemetrie_sendet_nicht():
    t, client = armed([200], aimon_url="")
    fill(t, 2)
    await t.flush()
    assert client.sent == []
