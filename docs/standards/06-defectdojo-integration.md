# Standard 06: Integracja dwukierunkowa z DefectDojo (Faza 6)

Szczegóły implementacyjne integracji opisanej w [`ADR-0008`](../adr/ADR-0008-defectdojo-bidirectional-integration.md).

---

## 1. Model danych (migracja `20261122000001_defectdojo_integration.sql`)

```
defectdojo_config        — singleton (id = TRUE): base_url, asi_public_url,
                           api_key_ciphertext/api_key_nonce (AES-256-GCM),
                           finding_scope ('changes'|'all_diffs'|'inventory'),
                           auto_push, pull_interval_minutes, enabled,
                           last_push_at, last_pull_at, last_error
dd_outbox                — kolejka push: kind ('scan_run'|'diff_event'|'manual_sync'),
                           asset_group_id, scan_run_id?, diff_event_id?,
                           status ('pending'|'processing'|'sent'|'failed'),
                           attempt_count, next_retry_at, last_error
dd_links                 — diff_event_id UNIQUE → dd_product_id, dd_engagement_id,
                           dd_test_id, dd_finding_id, dd_finding_status, dd_tags,
                           last_pushed_at, last_pulled_at
scan_runs.external_refs  — {"defectdojo": {"engagement_id": N, "test_id": M}}
asset_groups.external_refs — {"defectdojo": {"product_id": N}}
hosts.external_refs      — {"defectdojo": {"finding_id": N}}   (tylko scope=inventory)
diff_events.external_refs — rezerwacja na przyszłe rozszerzenia
```

## 2. Mapowanie ASI → DefectDojo

| ASI | DefectDojo | Uwagi |
|---|---|---|
| `asset_group.name` | `Product.name = "ASI: <name>"`, tag `asi` | tworzony leniwie przy pierwszym pushu; id w `external_refs` |
| `scan_run` | `Engagement` (`ASI scan <run_id[:8]>`) + `Test` (test_type `ASI Attack Surface Scan`) | Engagement `In Progress` → po pushu runa `Completed` |
| `diff_event` | `Finding` | `unique_id_from_tool = <diff_event UUID>` (idempotentny upsert) |
| `diff_event.event_kind/severity` | `Finding.severity` | Info/Low/Medium/High; kind jako tag (`confirmed_change`/`active_variance`) |
| `diff_event.bullet_items` | `Finding.title` (pierwszy bullet, ≤250 znaków) + `description` (pełna lista „myślników”) | zgodnie z notatką: czytelny changelog |
| host:port usługi | `Finding.component_name` (`service`/`technology` z bullet params) + opis | bez osobnych obiektów Endpoint (ADR-0008 §kompromisy) |
| `asi_public_url` | `Finding.references = <asi_public_url>/diffs/<diff_id>` | fallback `asi://diffs/<id>` |
| host aktywny (scope=inventory) | `Finding` Info, `unique_id_from_tool = "host:<host UUID>"` | id w `hosts.external_refs` |

Autoryzacja do DD: `Authorization: Token <API key>` (konto użytkownika **AGH** w DefectDojo).

## 3. Przepływ push (ASI → DD)

```
diff wykryty (worker_internal, ta sama transakcja co INSERT diff_events)
  → enqueue_dd_for_diff (jeśli enabled && auto_push && scope obejmuje kind)
scan_run → completed
  → enqueue_dd_for_run (cały run)
UI: "Synchronizuj teraz" / "Wyślij do DD"
  → manual_sync / natychmiastowy push_single_diff
        ↓
outbox worker (co 10 s, FOR UPDATE SKIP LOCKED, limit 10)
  → ensure Product → Engagement → Test Type → Test (idempotentnie, cache w external_refs)
  → upsert Finding (GET by unique_id_from_tool → PATCH | POST)
  → upsert dd_links + last_pushed_at
  → sent | failed + backoff [10s, 30s, 2m, 10m, 30m]
  → SSE: defectdojo.outbox / defectdojo.push
```

Scope `inventory` dodatkowo publikuje aktywne hosty grupy jako findingi `Info` i zamyka Engagement (`Completed`).

## 4. Przepływ pull (DD → ASI)

Wątek co `pull_interval_minutes` (min 1):

1. `SELECT diff_event_id, dd_finding_id FROM dd_links WHERE dd_finding_id IS NOT NULL`;
2. `GET /api/v2/findings/?id__in=<ids>&limit=100&offset=…` (paginacja);
3. dla każdego findingu — aktualizacja **wszystkich** linków z tym `dd_finding_id`:
   `dd_finding_status`, `dd_tags`, `last_pulled_at` (tylko gdy faktycznie zmienione);
4. SSE `defectdojo.finding_updated` → UI odświeża badge „DD #id · status” na liście diffów;
5. `defectdojo_config.last_pull_at = NOW()`.

Statusy DD (`active`, `mitigated`, `false_positive`, `risk_accepted`, …) są tylko **odczytywane** — ASI nie modyfikuje statusów w DD automatycznie (triage należy do analityka w DD).

## 5. API (publiczne, tag `Integrations`)

| Metoda | Ścieżka | Permisja | Opis |
|---|---|---|---|
| GET | `/api/v1/integrations/defectdojo` | `view_inventory_and_diffs` | config + `pending_outbox` (sekret NIGDY nie wychodzi) |
| PUT | `/api/v1/integrations/defectdojo` | `manage_external_integrations` | upsert; `api_key` opcjonalny (null = bez zmiany) |
| POST | `/api/v1/integrations/defectdojo/test-connection` | `manage_external_integrations` | ping `GET /api/v2/products/?limit=1` |
| POST | `/api/v1/integrations/defectdojo/sync` | `manage_external_integrations` | `{asset_group_id?}` → 202 + `enqueued` |
| POST | `/api/v1/integrations/defectdojo/push/{diff_event_id}` | `manage_external_integrations` | push pojedynczego diffa (poza scope) |
| GET | `/api/v1/integrations/defectdojo/link/{diff_event_id}` | `view_inventory_and_diffs` | `DdLinkDto` |
| GET | `/api/v1/integrations/defectdojo/outbox` | `view_inventory_and_diffs` | kolejka (paginacja) |

Błędy: RFC 9457 `application/problem+json` (walidacja `base_url` = URL, `pull_interval_minutes` 1–1440).

## 6. Bezpieczeństwo

* API key: AES-256-GCM (`ASI_MASTER_KEY`), tylko ciphertext w bazie; UI pokazuje jedynie `has_api_key`.
* RBAC: mutacje tylko dla `Admin` (`manage_external_integrations`); odczyt dla wszystkich ról z `view_inventory_and_diffs`.
* TLS do DD (rustls, TLS 1.2+); timeout connect 10 s / request 30 s.
* `audit_logs`: `defectdojo.config_updated` (z `api_key_changed`, bez wartości), akcje systemowe dla push/pull.
* Sekrety w odpowiedziach DD (np. tagi) są tylko przepisywane do `dd_links.dd_tags`.

## 7. UI

* Zakładka **„Integracje (DefectDojo)”**: formularz configu (base_url, asi_public_url, api_key hasłem, scope, auto_push, pull interval, enabled), przyciski *Zapisz* / *Test połączenia* / *Synchronizuj teraz*, kafel statusu (last push/pull, pending, last_error) i tabela outbox (auto-refresh 10 s).
* Zakładka **„Diffy i zmiany”**: każdy diff ma badge `DD #<finding_id> · <status>` (z pull) oraz przycisk *Wyślij do DD* (dla Admina).
* SSE: `defectdojo.outbox`, `defectdojo.push`, `defectdojo.finding_updated`.
* i18n pl/en (parzystość kluczy pilnuje `npm run check:i18n`).

## 8. Testy i środowisko deweloperskie

* `crates/asi-api/tests/dd_integration.rs`:
  * `dd_client_upsert_is_idempotent_and_pull_reads_status` — mock API v2 (axum) bez bazy: idempotentny upsert, pull statusów/tagów, 401 dla złego klucza;
  * `live_db_dd_config_push_pull_and_rbac` (`#[ignore]`, wymaga `DATABASE_URL`) — pełny flow przez REST: config → test-connection → push → link → pull (`mitigated`) → outbox → RBAC 403 dla ReadOnly → sync 202.
* `docker compose -f deploy/docker-compose.dev.yml --profile dd up -d` podnosi lokalnego DefectDojo (dev) obok mock-labu.
* Polecenia weryfikacyjne: `make ci` (fmt + clippy + testy + UI).

## 9. Runbook produkcyjny (AGH)

1. W DefectDojo utwórz użytkownika serwisowego **AGH** i skopiuj jego **API Key** (User → API Key).
2. W ASI (rola Admin) → *Integracje (DefectDojo)*: podaj `base_url` DD, `asi_public_url`, API key, wybierz scope, zaznacz `auto_push` i `enabled` → *Zapisz*, potem *Test połączenia*.
3. Opcjonalnie *Synchronizuj teraz*, aby od razu wysłać ostatni stan.
4. W DD produkty pojawią się jako `ASI: <nazwa grupy>`; każdy zakończony skan to Engagement z testem `ASI Attack Surface Scan` i findingami per diff.
5. Statusy ustawiane w DD (np. `mitigated`, `false_positive`) wracają do ASI w ciągu `pull_interval_minutes` i widać je na liście diffów (badge `DD #… · status`).

### 9.1 Pułapki wdrożeniowe (sprawdzone w dev)

- **Port kontenera DD:** obraz `defectdojo/defectdojo-django` nasłuchuje uWSGI na **8081** wewnątrz kontenera — compose mapuje `127.0.0.1:8081:8081` (mapowanie na 8000 daje „socket hang up”).
- **Brak `Product_Type` w świeżej bazie DD:** API v2 odrzuca `POST /products/` (404 „No Product_Type matches”). `make dd-init` tworzy `AGH Default`; w produkcji utwórz typ ręcznie. Kod (`ensure_product`) bierze pierwszy dostępny typ dynamicznie.
- **Wymagane pola findingu w nowym API v2:** `found_by` (lista testów) i `numerical_severity` (`S0`–`S5`) — payload je zawiera (`dd_numerical_severity`).
- **Keep-alive vs uWSGI:** klient DD ma wyłączony pool (`pool_max_idle_per_host(0)`) — uWSGI zamyka bezczynne połączenia i reqwest na POST dostawałby „error sending request”.
- **Wygasające tokeny DRF:** `ExpiringTokenAuthentication` — raporte „Invalid token” po czasie → wygeneruj nowy (`make dd-token` w dev; w prod nowy API Key użytkownika serwisowego).
- **Osierocone wpisy outbox:** tick co 5 min wraca `processing` → `pending`; błędy retry: 10s/30s/2m/10m/30m (`SKIP LOCKED`).
- **Test `dd_integration` nadpisuje singleton `defectdojo_config`** mockiem — po `cargo test --include-ignored` w dev przywróć konfigurację (`make dd-setup`).
