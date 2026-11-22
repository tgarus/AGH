# ADR-0008: Dwukierunkowa integracja z DefectDojo (Faza 6)

* **Status:** Zaakceptowana i zaimplementowana (Faza 6)
* **Data:** 2026-11-21
* **Powiązane dokumenty:** [`ADR-0007`](ADR-0007-deferred-external-integrations-defectdojo.md) (odroczenie), [`system_architecture_attack_surface_intelligence.md`](../../system_architecture_attack_surface_intelligence.md), [`docs/standards/06-defectdojo-integration.md`](../standards/06-defectdojo-integration.md), notatka projektowa: `DefectDojo ⇄ Rozwiązanie ⇄ Skanery (najlepiej OpenSource)`, `AGH będzie użytkownikiem`

## Kontekst

Po ustabilizowaniu autonomicznego rdzenia ASI (Fazy 1–5) wracamy do integracji z DefectDojo — zgodnie z notatką projektową ASI pełni rolę **middleware/wrappera** między DefectDojo a skanerami open-source: `DefectDojo ⇄ ASI ⇄ Skanery`. W DefectDojo zakładamy dedykowane konto użytkownika **„AGH"** (API key), a ASI publikuje tam wyniki i pobiera z powrotem statusy triażu.

Decyzje użytkownika z warsztatu (20 pytań):

1. **Kierunek: dwukierunkowy (⇄)** — ASI → DD publikuje findingi; DD → ASI wracają statusy i tagi findingów.
2. **Zakres findingów: konfigurowalny** — `changes` (tylko `confirmed_change`) / `all_diffs` (także `active_variance`) / `inventory` (jw. + każdy aktywny host jako finding `Info`).
3. **Mapowanie struktury: decyzja projektowa ASI** (patrz niżej).
4. **Tryb wysyłki: oba** — automatyczny outbox po każdym zakończonym skanie + ręczny push/sync z UI.

## Decyzja

### 1. Mapowanie encji (uzasadnienie: przeznaczenie DefectDojo)

| ASI | DefectDojo | Uzasadnienie |
|---|---|---|
| `asset_group` (grupa zasobów, np. podsieć/wydział) | **Product** (`ASI: <nazwa>`) | Product w DD to długowieczny obszar z własnymi tagami, członkami zespołu i business criticality — dokładnie to, czym jest asset group. |
| `scan_run` (pojedynczy przebieg) | **Engagement** + jeden **Test** typu `ASI Attack Surface Scan` | Engagement ma daty rozpoczęcia/zakończenia i status (`In Progress` → `Completed`) — idealnie pasuje do przebiegu skanu; historia przebiegów zostaje w DD. |
| `diff_event` (pojedyncza zmiana) | **Finding** w tym Teście | Finding to pojedyncza obserwacja z severity, statusem triażu i tagami — 1:1 z diff_event. |

ID powiązań trzymamy w `external_refs JSONB` (asset_groups, scan_runs, hosts) oraz w tabeli `dd_links` (per diff_event: product/engagement/test/finding id + ostatni status z DD).

### 2. Bezpośrednie API v2 zamiast `reimport-scan`

**Nie używamy** `POST /tests/{id}/reimport-scan/` (ADR-0007 wskazywał pułapki przy mikro-paczkach: reimport zamyka wszystkie findingi nieobecne w pliku, co przy paczkowanym skanowaniu zamykałoby aktywne findingi przedwcześnie). Zamiast tego:

* upsert findinga po `unique_id_from_tool = <diff_event UUID>`: `GET /api/v2/findings/?unique_id_from_tool=…` → `PATCH` gdy istnieje, inaczej `POST /api/v2/findings/`;
* push całego runa = push wszystkich jego diffów (z filtrem scope) + zamknięcie Engagementu (`status=Completed`);
* pull: `GET /api/v2/findings/?id__in=…` dla wszystkich linkowanych findingów → aktualizacja `dd_links.dd_finding_status/dd_tags` + event SSE `defectdojo.finding_updated`.

### 3. Kolejka outbox z retry (niezawodność push)

Tabela `dd_outbox` (`kind`: `scan_run` | `diff_event` | `manual_sync`). Wątek w `asi-api` (co 10 s) bierze `pending/failed` due (`FOR UPDATE SKIP LOCKED`), wykonuje push i oznacza `sent`, przy błędzie `failed` z backoff `10s, 30s, 2m, 10m, 30m` (jak kolejka powiadomień). Hooki:

* po każdym wykrytym diffie (w transakcji ingestu wyników) — `enqueue_dd_for_diff` (z uwzględnieniem `finding_scope` i `auto_push`);
* gdy `scan_run` przechodzi w `completed` — `enqueue_dd_for_run` (push całego runa + zamknięcie engagementu; przy scope `inventory` dodatkowo hosty grupy jako findingi `Info` z `unique_id_from_tool = host:<uuid>`).

### 4. Bezpieczeństwo

* API key DD przechowywany wyłącznie jako ciphertext **AES-256-GCM** (`defectdojo_config.api_key_ciphertext/api_key_nonce`, klucz `ASI_MASTER_KEY`) — nigdy nie wychodzi z backendu (`has_api_key` w DTO).
* Autoryzacja DD: header `Authorization: Token <api_key>`; konto „AGH” w DD.
* RBAC: odczyt config/linków/outbox = `view_inventory_and_diffs`; zapis configu, test-connection, sync, push = `manage_external_integrations` (tylko **Admin**).
* Cała komunikacja ASI ↔ DD po HTTPS (TLS 1.2+ wymuszony przez rustls); base_url walidowany jako URL.
* Audit: każda zmiana configu i akcja sync/push ląduje w `audit_logs`.

### 5. Konfiguracja (singleton `defectdojo_config`)

`base_url`, `asi_public_url` (link w polu `references` findinga), `api_key` (write-only), `finding_scope`, `auto_push`, `pull_interval_minutes` (1–1440), `enabled`, `last_push_at`, `last_pull_at`, `last_error`.

## Endpointy (vše pod `/api/v1/integrations/defectdojo`)

| Metoda | Ścieżka | Permisja | Opis |
|---|---|---|---|
| GET | `/` | view | config (bez sekretu) + licznik pending outbox |
| PUT | `/` | manage_external_integrations | upsert configu; `api_key: null` = zostaw stary |
| POST | `/test-connection` | manage_external_integrations | `GET /api/v2/products/?limit=1` jako ping |
| POST | `/sync` | manage_external_integrations | enqueue `manual_sync` (jedna grupa lub wszystkie) → 202 |
| POST | `/push/{diff_event_id}` | manage_external_integrations | natychmiastowy push pojedynczego diffa (poza scope) |
| GET | `/link/{diff_event_id}` | view | `DdLinkDto` (id findinga w DD + status + tagi) |
| GET | `/outbox` | view | paginowana kolejka outbox |

## Konsekwencje i kompromisy

* **Pozytywne:** prawdziwa dwukierunkowość (statusy triażu z DD widoczne w ASI i w SSE), odporność na awarie DD (outbox + retry), idempotentność (unique_id_from_tool), brak zamykania aktywnych findingów przy paczkowanym skanowaniu, pełny audit.
* **Koszty/kompromisy:**
  * nie używamy `reimport-scan` — „zamykanie” znikniętych usług w DD robimy jako osobny diff (`- usługa …`) publikowany jako finding, a nie przez reimport;
  * nie tworzymy osobnych obiektów `Endpoint` w DD (host:port leci w `component_name`/opisie) — mniej wywołań API, mniej punktów awarii; można dodać później bez zmiany kontraktu;
  * pull jest okresowy (min 1 min), nie eventowy — DD nie oferuje webhooków per-finding bez konfiguracji, a polling jest wystarczający dla triażu.

## Weryfikacja

* `crates/asi-api/tests/dd_integration.rs`:
  * `dd_client_upsert_is_idempotent_and_pull_reads_status` — klient vs mock API v2 (upsert idempotentny, pull statusów, 401 przy złym kluczu);
  * `live_db_dd_config_push_pull_and_rbac` (wymaga `DATABASE_URL`) — pełny flow: PUT config → test-connection → push diff → `dd_links` z `dd_finding_id` → pull zmienia status na `mitigated` → enqueue outbox → RBAC (ReadOnly dostaje 403 na PUT/sync) → manual sync 202.
