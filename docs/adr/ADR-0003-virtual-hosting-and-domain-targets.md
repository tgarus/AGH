# ADR-0003: Obsługa celów domenowych i Virtual Hostingu (rDNS + TLS SAN + SNI)

* **Status:** Zaakceptowana
* **Data:** 2026-11-21
* **Powiązane dokumenty:** [`02-domain-and-data-model.md`](../standards/02-domain-and-data-model.md), [`04-pipeline-diff-and-instability.md`](../standards/04-pipeline-diff-and-instability.md)

## Kontekst
W sieci akademickiej AGH na pojedynczym adresie IP (np. za serwerem reverse proxy lub na hoście współdzielonym) często działa kilkanaście niezależnych aplikacji webowych rozróżnianych wyłącznie po nazwie domenowej w nagłówku `Host` i rozszerzeniu TLS `SNI`. Skanowanie samego adresu IP wykryłoby wyłącznie domyślny vhost, pomijając realne instancje Shadow IT.

## Decyzja
1. **Model celów:** Grupy Zasobów przyjmują zarówno **IP / bloki CIDR**, jak i **domeny / vhosty** (`asset_group_targets`).
2. **Automatyczne wzbogacanie w Etapie 2:** Dla każdego aktywnego IP silnik zbiera dodatkowe nazwy hostów z **odwrotnego DNS (`PTR` / rDNS)** oraz z pól **`SAN` (Subject Alternative Name)** certyfikatów TLS (`x509-parser`), zapisując je w `host_hostnames` z oznaczeniem źródła (`user_input`, `rdns`, `tls_san`).
3. **Fingerprinting per vhost w Etapie 3:** Etap 3 wykonuje pasywny fingerprinting dla każdej unikalnej krotki `(host_port_id, vhost, scheme)`, ustawiając jawnie nagłówek `Host` oraz `SNI` (z adresem IP jako fallback, gdy brak nazw domenowych).

## Konsekwencje i kompromisy
* **Pozytywne:** Pełna widoczność aplikacji ukrytych za Virtual Hostingiem i reverse proxy bez duplikowania skanów portów w Etapie 1 i 2.
* **Koszt:** Większa liczba zapytań HTTP w Etapie 3 na hostach z dużą liczbą nazw `SAN` — kontrolowana przez wspólną blokadę `ip_locks`, limity współbieżności oraz deduplikację po krotce `(host_port_id, vhost, scheme)`.
