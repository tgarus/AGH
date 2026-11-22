# ADR-0004: Natywny format sygnatur `FingerprintHub v4` (YAML) jako jeden standard

* **Status:** Zaakceptowana
* **Data:** 2026-11-21
* **Powiązane dokumenty:** [`03-api-worker-and-events.md`](../standards/03-api-worker-and-events.md), [`04-pipeline-diff-and-instability.md`](../standards/04-pipeline-diff-and-instability.md)

## Kontekst
Projekt czerpie inspirację z repozytorium `0x727/FingerprintHub` oraz silnika `ObserverWard`. W praktyce istnieje pokusa wprowadzenia własnego uproszczonego formatu reguł w ASI i konwertowania reguł zewnętrznych, co jednak z czasem prowadzi do rozjazdu funkcji, błędów konwersji i problemów z synchronizacją aktualizacji ze społecznościowego repozytorium.

## Decyzja
Standardowym i **jedynym formatem sygnatur** w ASI jest **natywny format `FingerprintHub v4` (YAML)** (kompatybilny z konwencjami Nuclei / ObserverWard v4):
* Dotyczy to zarówno reguł wbudowanych, reguł synchronizowanych z repozytorium `FingerprintHub`, jak i własnych sygnatur tworzonych przez analityków w panelu UI (`signature_rules`).
* Każda reguła przechodzi przez walidator YAML przed zapisem do bazy danych (`POST /api/v1/signatures/validate`).
* Natywny silnik Etapu 3 w Ruście wykonuje szybkie dopasowania pasywne bezpośrednio w pamięci, a opcjonalnie (gdy polityka na to zezwala) może oddelegować wybrane szablony wieloetapowe do `Nuclei` bez zmiany formatu reguł.

## Konsekwencje i kompromisy
* **Pozytywne:** Zero stratnych konwersji, bezpośrednie korzystanie z bogatej bazy sygnatur `FingerprintHub`, możliwość przenoszenia reguł między ASI a `ObserverWard` / `Nuclei`.
* **Koszt:** Silnik w Ruście musi zaimplementować podzbiór ewaluatora matcherów YAML (status, word, regex, dsl/favicon `mmh3`, header) i jasno raportować przy walidacji ewentualne zaawansowane dyrektywy wymagające `Nuclei`.
