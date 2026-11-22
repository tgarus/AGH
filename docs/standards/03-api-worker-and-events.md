# Standard 03: Kontrakty API, protokół workera, SSE, powiadomienia i Import/Export

**Status:** Obowiązujący (Faza 0)  
**Data:** 2026-11-21

---

## 1. Standard publicznego REST API (`/api/v1/*`)

### 1.1. Konwencje ogólne
* **Wersjonowanie:** Wszystkie publiczne endpointy pod prefiksem `/api/v1/...`.
* **Serializacja:** JSON `snake_case`, daty w ISO 8601 UTC (`2026-11-21T15:00:00Z`), brak typów dynamicznych bez schematu OpenAPI.
* **Paginacja list:** Parametry zapytania `page` (domyślnie `1`), `per_page` (domyślnie `50`, maks. `200`), `sort_by`, `sort_dir` (`asc` | `desc`).
  Odpowiedź listowa ma jednolitą kopertę:
  ```json
  {
    "items": [],
    "pagination": { "page": 1, "per_page": 50, "total_items": 1240, "total_pages": 25 }
  }
  ```

### 1.2. Standard błędów: RFC 9457 (`application/problem+json`)
Każdy błąd HTTP `4xx`/`5xx` zwraca obiekt zgodny z RFC 9457:
```json
{
  "type": "https://asi.agh.edu.pl/errors/validation-failed",
  "title": "Validation Failed",
  "status": 422,
  "detail": "One or more request fields failed validation.",
  "instance": "/api/v1/asset-groups",
  "error_code": "VALIDATION_ERROR",
  "request_id": "01934d8a-7c1b-7b22-a31c-9f2a11c3d012",
  "violations": [
    { "field": "targets[0].value", "code": "INVALID_CIDR", "message": "Expected valid IPv4/IPv6 CIDR block." }
  ]
}
```

### 1.3. Katalog endpointów publicznych (`/api/v1/*`)

| Moduł | Endpointy główne |
|---|---|
| **System / Kontrakt** | `GET /api/v1/healthz`, `GET /api/v1/readyz`, `GET /api/v1/openapi.json` |
| **Auth** | `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`, `POST /api/v1/auth/logout`, `GET /api/v1/auth/me` |
| **Użytkownicy & Audyt** | `GET/POST /api/v1/users`, `PATCH/DELETE /api/v1/users/{id}`, `GET /api/v1/audit-logs` |
| **Grupy & Polityki** | `GET/POST /api/v1/asset-groups`, `GET/PATCH/DELETE /api/v1/asset-groups/{id}`, `POST /api/v1/asset-groups/{id}/targets`, `GET/POST/PATCH/DELETE /api/v1/policies`, `GET/POST/DELETE /api/v1/ignored-targets` |
| **Skany** | `POST /api/v1/scans/preflight`, `GET/POST /api/v1/scans`, `GET /api/v1/scans/{id}`, `POST /api/v1/scans/{id}/pause`, `POST /api/v1/scans/{id}/resume`, `POST /api/v1/scans/{id}/stop` |
| **Hosty & Usługi** | `GET /api/v1/hosts`, `GET /api/v1/hosts/{id}`, `PATCH /api/v1/hosts/{id}` *(wyłącznie pola analityczne)*, `POST /api/v1/hosts/{id}/tarpit-override`, `GET /api/v1/services`, `GET /api/v1/clusters` *(grupowanie po `favicon_mmh3`, tytule, CMS)* |
| **Diffy** | `GET /api/v1/diffs`, `GET /api/v1/diffs/{id}`, `POST /api/v1/diffs/{id}/acknowledge` |
| **Sygnatury** | `GET/POST /api/v1/signatures`, `GET/PATCH/DELETE /api/v1/signatures/{id}`, `POST /api/v1/signatures/validate`, `POST /api/v1/signatures/sync` |
| **Powiadomienia** | `GET/POST /api/v1/notifications/channels`, `PATCH/DELETE /api/v1/notifications/channels/{id}`, `POST /api/v1/notifications/channels/{id}/test` |
| **Workery** | `GET /api/v1/workers`, `POST /api/v1/workers/tokens`, `POST /api/v1/workers/{id}/revoke` |
| **Import / Export** | `POST /api/v1/import/targets`, `POST /api/v1/import/signatures`, `GET /api/v1/export/hosts`, `GET /api/v1/export/diffs`, `GET /api/v1/export/services` |
| **Telemetria na żywo** | `GET /api/v1/events/stream` (SSE) |

---

## 2. Wewnętrzny protokół `asi-api` ↔ `asi-worker` (`/internal/v1/worker/*`)

Komunikacja odbywa się **wyłącznie przez HTTPS/TLS** z uwierzytelnieniem nagłówkiem `Authorization: Bearer <worker_service_token>`. Węzły `asi-worker` nigdy nie łączą się bezpośrednio z PostgreSQL.

### 2.1. Endpointy protokołu workera
1. `POST /internal/v1/worker/register` — rejestracja / zgłoszenie zdolności węzła (`naabu`, `masscan`, `nmap`, `nuclei`, wersje binarek, wersja bazy sygnatur, `max_concurrency`, `segment_tag`).
2. `POST /internal/v1/worker/chunks/lease` — żądanie kolejnej mikro-paczki. `asi-api` w jednej transakcji wykonuje:
   * wybór paczki z `scan_chunks` (`ORDER BY ... FOR UPDATE SKIP LOCKED`),
   * weryfikację wykluczeń i `ignored_targets`,
   * atomowe pozyskanie blokad Per-IP w tabeli `ip_locks` z uwzględnieniem `cooldown_until`,
   * zwrócenie paczki wraz z zamrożoną konfiguracją polityki, czasem TTL dzierżawy (np. `60s`) oraz listą wykluczeń.
   * Jeśli brak dostępnych paczek, API zwraca `204 No Content`.
3. `POST /internal/v1/worker/chunks/{chunk_id}/heartbeat` — wysyłane co `15s` podczas trwania paczki; przedłuża `lease_expires_at` i odświeża `ip_locks`. Odpowiedź API zawiera dyrektywę sterującą (`continue` | `graceful_stop` | `kill_now`).
4. `GET /internal/v1/worker/control/stream` — stały kanał SSE pomiędzy `asi-api` a podłączonym workerem dostarczający sygnały **Hard Kill Switch** (`stop_scan_run`, `stop_chunk`, `reload_signatures`) w czasie `< 200 ms`, bez czekania na kolejny cykl heartbeat.
5. `POST /internal/v1/worker/chunks/{chunk_id}/results` — przesłanie znormalizowanych wyników Etapów 1–3, statystyk czasowych oraz ewentualnych anomalii (`probable_tarpit`). Wymaga klucza idempotencji `(chunk_id, attempt_no)`, aby powtórzenie żądania po błędzie sieci nie dublowało zapisu.
6. `POST /internal/v1/worker/chunks/{chunk_id}/release` — bezpieczne oddanie przerwanej paczki (po `Stop`, `Pause` lub końcu okna czasowego) ze stanem `PENDING` z powrotem do kolejki oraz zwolnieniem blokad `ip_locks`.

### 2.2. Diagram sekwencji dzierżawy i Hard Kill Switcha

```mermaid
sequenceDiagram
    participant UI as "asi-ui"
    participant API as "asi-api (Axum)"
    participant DB as "asi-db (PostgreSQL)"
    participant W as "asi-worker (Tokio)"

    W->>API: "GET /internal/v1/worker/control/stream (SSE)"
    W->>API: "POST /internal/v1/worker/chunks/lease"
    API->>DB: "BEGIN; SELECT ... FROM scan_chunks FOR UPDATE SKIP LOCKED + LOCK ip_locks; COMMIT"
    DB-->>API: "chunk_id, targets, policy_snapshot"
    API-->>W: "200 OK (lease + TTL 60s)"

    loop "Co 15s w trakcie skanu Etapow 1-3"
        W->>API: "POST /internal/v1/worker/chunks/{id}/heartbeat"
        API->>DB: "UPDATE lease_expires_at"
        API-->>W: "200 OK { directive: continue }"
    end

    UI->>API: "POST /api/v1/scans/{scan_id}/stop"
    API->>DB: "UPDATE scan_runs SET status = stopping"
    API-->>W: "SSE control: { action: stop_scan_run, grace_seconds: 3 }"
    Note over W: "SIGTERM -> oczekiwanie do 3s -> SIGKILL -pgid"
    W->>API: "POST /internal/v1/worker/chunks/{id}/release (czesciowe wyniki opcjonalnie)"
    API->>DB: "UPDATE scan_chunks SET status = pending; DELETE FROM ip_locks"
    API-->>UI: "SSE event: scan.status_changed (stopped)"
```

---

## 3. Schemat zdarzeń SSE dla UI (`/api/v1/events/stream`)

Kanał SSE uwierzytelniany jest bieżącym JWT (przekazywanym przez `fetch`-based SSE lub krótkożyjący jednorazowy bilet sesyjny SSE). Obsługuje nagłówek `Last-Event-ID` do wznowienia po chwilowym rozłączeniu.

| Typ zdarzenia (`event:`) | Przeznaczenie | Kluczowe pola `data` (JSON) |
|---|---|---|
| `scan.progress` | Postęp mikro-paczek i Live EMA | `scan_run_id`, `completed_chunks`, `total_chunks`, `percent`, `ema_chunk_ms`, `eta_seconds`, `estimated_finish_at` |
| `scan.status_changed` | Zmiana cyklu życia skanu | `scan_run_id`, `previous_status`, `current_status`, `reason` |
| `diff.detected` | Nowe zdarzenie Diff Engine | `diff_event_id`, `host_id`, `ip_addr`, `event_kind` (`confirmed_change` \| `active_variance`), `severity`, `bullet_items` |
| `host.anomaly` | Wykrycie `probable-tarpit` lub niestabilności | `host_id`, `ip_addr`, `anomaly_type` (`probable_tarpit` \| `unstable`), `open_port_count` |
| `worker.status` | Zmiana dostępności węzła wykonawczego | `worker_id`, `name`, `status`, `active_chunks` |

Przykładowy ładunek `diff.detected`:
```json
{
  "event_id": "01934d92-21ab-7001-88c1-44019e0f2011",
  "occurred_at": "2026-11-21T15:10:04Z",
  "diff_event_id": "01934d92-21aa-7112-9012-119820aa0012",
  "host_id": "01934d11-0001-7000-8000-000000000105",
  "ip_addr": "10.20.30.40",
  "event_kind": "confirmed_change",
  "severity": "medium",
  "bullet_items": [
    { "op": "+", "key": "service_added", "params": { "port": 8443, "proto": "tcp", "scheme": "https", "path": "/admin" } }
  ]
}
```

---

## 4. Kontrakt `NotificationSink` i webhooki

### 4.1. Abstrakcja w `asi-common` / `asi-api`
Wszystkie zewnętrzne powiadomienia przechodzą przez wspólny asynchroniczny trait `NotificationSink`:
* `WebhookJsonSink` — generyczny JSON HTTP POST.
* `SlackSink`, `TeamsSink`, `MattermostSink` — adaptery formatujące komunikaty Markdown/Adaptive Card na podstawie `bullet_items`.
* `SmtpSink` *(opcjonalny)* — wysyłka maila dla zdarzeń `confirmed_change` / raportów zbiorczych `active_variance`.

### 4.2. Bezpieczeństwo i ponawianie webhooków
* Każdy webhook JSON wysyłany jest z nagłówkami:
  * `X-ASI-Event: diff.detected`
  * `X-ASI-Delivery-Id: <uuid>`
  * `X-ASI-Timestamp: <unix_epoch>`
  * `X-ASI-Signature-256: sha256=<hex_hmac>` (HMAC-SHA256 z `"{timestamp}.{raw_body}"` przy użyciu odszyfrowanego sekretu kanału).
* **Retry policy:** Kolejka w `notification_deliveries` ponawia próby z wykładniczym opóźnieniem (`10s`, `30s`, `2m`, `10m`, `30m`), maksymalnie `5` prób, z timeoutem pojedynczego żądania `5s`.

---

## 5. Standard Import / Export (wyłącznie JSON)

Wszystkie eksporty oraz importy realizowane są **wyłącznie w formacie JSON** z jednolitą kopertą wersjonującą:
```json
{
  "schema_version": "1.0",
  "exported_at": "2026-11-21T15:15:00Z",
  "entity_type": "targets",
  "items": []
}
```
* **Import celów (`POST /api/v1/import/targets`):** Akceptuje wyłącznie obiekt JSON z `schema_version: "1.0"`, `asset_group_id` oraz listą `{ "target_type": "cidr|ip|domain|exclude_cidr", "value": "...", "notes": "..." }`. Walidacja odrzuca błędne formaty (RFC 9457) zanim cokolwiek zapisze do DB (tryb transakcyjny *all-or-nothing* z obsługą `dry_run: true`).
* **Eksport (`GET /api/v1/export/*`):** Zwraca ustrukturyzowaną kopertę JSON (`schema_version: "1.0"`) m.in. dla `/api/v1/export/targets`, `/api/v1/export/policies`, `/api/v1/export/ignored-targets`, a w kolejnych fazach także dla hostów, usług i diffów.
* **Import sygnatur (`POST /api/v1/import/signatures`):** Paczka reguł YAML `FingerprintHub v4` w JSON walidowana parserem przed zapisem.
