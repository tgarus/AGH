# Dokumentacja techniczna i standaryzacja — Attack Surface Intelligence (ASI)

Ten katalog zawiera kanoniczne standardy inżynieryjne, kontrakty interfejsów, model danych, rekordy decyzji architektonicznych (ADR) oraz plan realizacji platformy **Attack Surface Intelligence (ASI)** dla Centrum Bezpieczeństwa Informacji AGH.

---

## Polityka językowa projektu

| Obszar | Obowiązujący język | Zasada szczegółowa |
|---|---|---|
| **Kod źródłowy (Rust, TypeScript, SQL)** | Angielski (`en`) | Nazwy typów, funkcji, zmiennych, modułów, migracji SQL i komentarzy w kodzie wyłącznie po angielsku. |
| **API, schemat DB, logi, błędy techniczne, testy** | Angielski (`en`) | Ścieżki URL, klucze JSON (`snake_case`), nazwy kolumn/tabel, logi `tracing` i pola RFC 9457 po angielsku. |
| **Dokumentacja projektu, specyfikacje, ADR-y** | Polski (`pl`) | Dokumenty w `docs/` oraz opis architektury pisane po polsku z zachowaniem kanonicznych identyfikatorów technicznych (np. `asi-worker`, `scan_chunks`, `probable-tarpit`). |
| **Interfejs użytkownika (`asi-ui`)** | i18n: **Polski domyślnie (`pl`)**, gotowy **Angielski (`en`)** | Brak tekstów zakodowanych na sztywno w komponentach — każdy napis przechodzi przez `react-i18next`. |

---

## Nawigacja po dokumentacji

### Szybki start
* **[`QUICKSTART.md`](QUICKSTART.md)** — jak uruchomić całość od zera (WSL + Docker), pierwszy skan demo, lokalny DefectDojo, FAQ — wszystko po polsku.

### Dokument główny
* [`system_architecture_attack_surface_intelligence.md`](../system_architecture_attack_surface_intelligence.md) — wizja systemu, pryncypia projektowe, diagram modułowy, topologia wdrożeniowa.

### Standardy techniczne (`docs/standards/`)

| Dokument | Zakres |
|---|---|
| [`01-engineering-standards.md`](standards/01-engineering-standards.md) | Układ monorepo, konwencje Rust i React/TypeScript, i18n, logowanie `tracing`, OpenAPI jako Single Source of Truth, CI oraz środowisko **Docker Mock-Lab**. |
| [`02-domain-and-data-model.md`](standards/02-domain-and-data-model.md) | Słownik domenowy, zasada *Scan-First Truth*, pełny schemat PostgreSQL (tabele, indeksy, `SKIP LOCKED`, `ip_locks`, `external_refs`) oraz diagram ER. |
| [`03-api-worker-and-events.md`](standards/03-api-worker-and-events.md) | Publiczne REST API (`/api/v1/*`), błędy RFC 9457, wewnętrzny protokół workerów (`/internal/v1/worker/*`), strumień SSE, `NotificationSink` oraz Import/Export JSON. |
| [`04-pipeline-diff-and-instability.md`](standards/04-pipeline-diff-and-instability.md) | Potok Etapów 1–3, *Tarpit Guard*, *Virtual Hosting*, *Dynamic Micro-chunking*, EMA/ETA, *Hard Kill Switch*, maszyna stanów Diff Engine i detekcja niestabilności. |
| [`05-rbac-and-security.md`](standards/05-rbac-and-security.md) | Macierz uprawnień 4 ról RBAC, lokalne uwierzytelnianie (`Argon2id` + JWT + rotowany Refresh Token), hartowanie `systemd` workerów oraz szyfrowanie danych i sekretów. |
| [`06-defectdojo-integration.md`](standards/06-defectdojo-integration.md) | **Faza 6:** dwukierunkowa integracja z DefectDojo — model danych (`defectdojo_config`, `dd_outbox`, `dd_links`), mapowanie encji, push/pull, API `/api/v1/integrations/defectdojo`, bezpieczeństwo, UI, testy i runbook. |

### Decyzje architektoniczne i harmonogram
* [`docs/adr/README.md`](adr/README.md) — indeks decyzji architektonicznych (`ADR-0001` – `ADR-0008`).
* [`docs/roadmap.md`](roadmap.md) — podział prac na fazy realizacyjne (Fazy 0–5: rdzeń *standalone*; **Faza 6: integracja z DefectDojo — ukończona**, patrz [`ADR-0008`](adr/ADR-0008-defectdojo-bidirectional-integration.md)).

---

## Zasada nadrzędna w fazie rdzenia (*Standalone First*)

Zgodnie z [`ADR-0007`](adr/ADR-0007-deferred-external-integrations-defectdojo.md) platforma ASI powstawała w pierwszej kolejności jako **w pełni autonomiczny system** (Fazy 1–5). Integracja z DefectDojo została zrealizowana dopiero w **Fazie 6** ([`ADR-0008`](adr/ADR-0008-defectdojo-bidirectional-integration.md), [`standard 06`](standards/06-defectdojo-integration.md)) jako dwukierunkowy wrapper `DefectDojo ⇄ ASI ⇄ Skanery`, przy czym rdzeń pozostaje autonomiczny — wyłączenie integracji (`enabled=false`) nie wpływa na skanowanie i Diff Engine.
