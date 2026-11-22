# ADR-0005: Bezpiecznik *Tarpit Guard* bez cichego ucinania portów

* **Status:** Zaakceptowana
* **Data:** 2026-11-21
* **Powiązane dokumenty:** [`02-domain-and-data-model.md`](../standards/02-domain-and-data-model.md), [`04-pipeline-diff-and-instability.md`](../standards/04-pipeline-diff-and-instability.md), [`05-rbac-and-security.md`](../standards/05-rbac-and-security.md)

## Kontekst
Jednym z pryncypiów ASI jest **brak nakładania sztucznych limitów ucinających liczbę wykrytych portów** w Etapie 1. Jednocześnie w dużych sieciach zdarzają się firewalle typu *tarpit*, urządzenia brzegowe lub honeypoty odpowiadające `SYN-ACK` na tysiące lub wszystkie 65 535 portów. Przekazanie takiej listy bezpośrednio do `nmap -sV` w Etapie 2 unieruchomiłoby mikro-paczkę na wiele godzin i wyczerpało okno czasowe dla pozostałych hostów.

## Decyzja
Wprowadzamy mechanizm **konfigurowalnego bezpiecznika *Tarpit Guard*** w polityce skanowania (`scan_policies.tarpit_port_threshold`, domyślnie **`200`** otwartych portów na jednym IP):
1. **Brak ucinania danych z Etapu 1:** Wszystkie wykryte otwarte porty są w całości zapisywane w `host_ports` — system nigdy nie ucina cicho listy portów.
2. **Ochrona Etapu 2:** Gdy liczba otwartych portów na IP przekroczy próg, host otrzymuje flagę `is_probable_tarpit = true` (tag `probable-tarpit`), Etap 2 (`nmap -sV`) jest dla niego automatycznie wstrzymywany, a UI otrzymuje alert SSE `host.anomaly`.
3. **Kontrolowany wyjątek dla `Admina`:** Użytkownik z rolą `Admin` może świadomie przełączyć flagę `tarpit_override_force_sv = true` na konkretnym hoście, wymuszając wykonanie pełnego `nmap -sV` w kolejnym przebiegu (z wpisem do `audit_logs`).

## Konsekwencje i kompromisy
* **Pozytywne:** Chroni okna czasowe skanowania $>10\,000$ IP przed zawieszeniem przez pojedynczy firewall/honeypot, zachowując pełną wierność wyników discovery z Etapu 1.
* **Koszt:** Prawdziwy serwer wystawiający legalnie ponad 200 portów (np. duży serwer kontenerowy/laboratoryjny) trafi początkowo na blokadę Etapu 2 do czasu jednorazowej akceptacji przez `Admina` (lub podniesienia progu w polityce danej Grupy Zasobów).
