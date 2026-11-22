# ADR-0007: Odroczenie integracji z DefectDojo do Fazy 6 (autonomiczny rdzeń *standalone*)

* **Status:** Zaakceptowana
* **Data:** 2026-11-21
* **Powiązane dokumenty:** [`system_architecture_attack_surface_intelligence.md`](../../system_architecture_attack_surface_intelligence.md), [`02-domain-and-data-model.md`](../standards/02-domain-and-data-model.md), [`roadmap.md`](../roadmap.md)

## Kontekst
W pierwotnej wizji systemu ASI projektowano jako dwukierunkowy wrapper/middleware dla platformy DefectDojo. Szczegółowa analiza mechanizmów synchronizacji (mapowanie `Engagement`, pułapki `reimport-scan` przy mikro-paczkach oraz podział triażu) pokazała jednak, że przedwczesne wiązanie rdzenia ASI z detalami API DefectDojo komplikuje projekt na starcie i nie jest jeszcze potrzebne do uruchomienia podstawowej wartości systemu. Użytkownik podjął decyzję o czasowym pominięciu integracji z DefectDojo i powrocie do niej po ustabilizowaniu rdzenia.

## Decyzja
1. **Autonomiczny rdzeń (*Standalone First*):** W Fazach 1–5 ASI budowany i dostarczany jest jako w pełni samodzielna platforma (odkrywanie sieci, *Zero-Overlap Pipeline*, *Diff Engine*, zarządzanie hostami/tagami/listą ignorowanych, raportowanie i powiadomienia).
2. **Brak przedwczesnych tabel i kontraktów DefectDojo:** W Fazie 0–5 nie tworzymy tabel specyficznych dla DefectDojo (np. kolejek `dd_outbox`) ani sztywnego kontraktu mapowania `Product/Engagement/reimport-scan`.
3. **Neutralny punkt rozszerzenia:** Jedynym śladem przygotowawczym w modelu danych jest generyczna kolumna `external_refs JSONB DEFAULT '{}'` na tabelach `asset_groups` oraz `hosts`, pozwalająca w przyszłości powiązać encje ASI z dowolnym systemem zewnętrznym bez kosztownej refaktoryzacji rdzenia.
4. **Powrót w Fazie 6:** Pełna specyfikacja integracji z DefectDojo API v2 zostanie zaprojektowana i wdrożona jako osobny moduł w Fazie 6 po weryfikacji działania rdzenia ASI.

## Konsekwencje i kompromisy
* **Pozytywne:** Znacznie szybsza i prostsza ścieżka do działającego MVP, brak ryzyka oparcia architektury na nietrafionych założeniach co do API/workflow DefectDojo, czystszy model domenowy.
* **Koszt:** Gdy wrócimy do tematu w Fazie 6, konieczne będzie dopisanie dedykowanego standardu integracji, tabel synchronizacji/outboxa oraz widoków UI dla referencji z DefectDojo.
