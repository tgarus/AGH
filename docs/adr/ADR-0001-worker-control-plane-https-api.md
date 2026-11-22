# ADR-0001: Komunikacja `asi-worker` wyłącznie przez HTTPS API (`asi-api`)

* **Status:** Zaakceptowana
* **Data:** 2026-11-21
* **Powiązane dokumenty:** [`03-api-worker-and-events.md`](../standards/03-api-worker-and-events.md), [`05-rbac-and-security.md`](../standards/05-rbac-and-security.md)

## Kontekst
W pierwotnej wersji szkicu architektury występowała niespójność pomiędzy diagramem (w którym `asi-worker` pobierał paczki bezpośrednio z kolejki w PostgreSQL `asi-db`) a sekcją wdrożeniową (w której węzły skanujące rozlokowane w różnych segmentach sieci AGH łączyły się z `asi-api` po HTTPS/TLS). Bezpośredni dostęp rozproszonych węzłów skanujących do bazy danych wymagałby otwierania portu PostgreSQL między segmentami sieci, rozdawania poświadczeń DB i utrudniałby natychmiastowe egzekwowanie *Hard Kill Switcha*.

## Decyzja
Węzły wykonawcze **`asi-worker` komunikują się wyłącznie z `asi-api` przez HTTPS/TLS** (wewnętrzny kontrakt `/internal/v1/worker/*`), bez jakiegokolwiek bezpośredniego dostępu do `asi-db`.

* `asi-api` jako jedyny komponent zarządza tabelami `scan_chunks` (`FOR UPDATE SKIP LOCKED`) i `ip_locks` (*Per-IP Lock & Cooldown*), wystawia endpointy dzierżawy, przedłużania lease (`heartbeat`), raportowania wyników z kluczem idempotencji oraz kanał SSE `/internal/v1/worker/control/stream` dla natychmiastowego *Hard Kill Switcha* (`< 200 ms`).
* Workery uwierzytelniają się dedykowanymi tokenami serwisowymi (hashowanymi w bazie danych).

## Konsekwencje i kompromisy
* **Pozytywne:** Minimalna powierzchnia ekspozycji bazy PostgreSQL (brak dostępu z segmentów skanujących), centralne egzekwowanie wykluczeń i blokad Per-IP, możliwość prostego dodawania nowych węzłów skanujących za NAT/firewallem (wystarczy wychodzący HTTPS do `asi-api`).
* **Koszt:** `asi-api` staje się krytycznym pośrednikiem w dostarczaniu paczek i odbieraniu wyników — wymaga odpowiedniego buforowania połączeń w `sqlx` i idempotentnego endpointu ingestu wyników.
