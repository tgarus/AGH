# Attack Surface Intelligence (ASI)

Autonomiczna platforma dla **Centrum Bezpieczeństwa Informacji AGH** do cyklicznego, mało inwazyjnego odkrywania powierzchni ataku, monitorowania zmian (*Diff Engine*) oraz identyfikacji *Shadow IT*.

## Zakres rdzenia *Standalone* (Fazy 1–5)

- `crates/asi-common` — współdzielone modele domenowe, 4-poziomowy RBAC, błędy RFC 9457, kontrakty OpenAPI/Worker/SSE, parser `FingerprintHub v4` YAML, eksporty/importy JSON (`schema_version: "1.0"`) i trait `NotificationSink`.
- `crates/asi-api` — serwer sterujący (`Axum` + `SQLx` + `utoipa`):
  - lokalne konta (`Argon2id`, 15 min JWT w pamięci, rotowany Refresh Cookie z detekcją ponownego użycia, `audit_logs`),
  - orkiestrator mikro-paczek (*Dynamic Micro-chunking*, *Interleaving* podsieci, `FOR UPDATE SKIP LOCKED`, `ip_locks`, *Hard Kill Switch*),
  - silnik *Diff Engine* z progiem nieaktywności $K$, filtrowaniem szumu, wykrywaniem niestabilności w 4 slotach dobowych (`00_06`, `06_12`, `12_18`, `18_24`) i schedulerem okien czasowych,
  - moduł powiadomień (`WebhookJsonSink` + `HMAC-SHA256`, `SlackSink`, `TeamsSink`, `MattermostSink`, `SmtpSink`) szyfrujący sekrety `AES-256-GCM` wraz z kolejką retry (`10s`, `30s`, `2m`, `10m`, `30m`),
  - strumień **SSE** (`/api/v1/events/stream`) z historią i wznawianiem `Last-Event-ID`.
- `crates/asi-worker` — węzeł wykonawczy łączący się wyłącznie po HTTPS z `asi-api`, realizujący potok 3-etapowy bez redundancji (Etap 1 `Naabu`/`Masscan` + **Tarpit Guard**, Etap 2 `Nmap -sV` + TLS `rustls`/`x509-parser` + rDNS/SAN, Etap 3 Rust HTTP + `FingerprintHub v4` + `MurmurHash3` + opcjonalny `Nuclei`) oraz hot-reload sygnatur.
- `ui/` — kompletny panel `asi-ui` (React + TypeScript + Tailwind + shadcn/ui + TanStack Query + `react-i18next` `pl`/`en`).
- `deploy/` — `docker-compose.dev.yml` z izolowanym **Docker Mock-Lab** (`172.28.0.0/24`) i opcjonalnym lokalnym **DefectDojo** (`--profile dd`), utwardzony `docker-compose.prod.yml` (LUKS `PGDATA`) i unit `systemd` z `CAP_NET_RAW`.

## Faza 6 — dwukierunkowa integracja z DefectDojo (ADR-0008)

Zgodnie z [`ADR-0008`](docs/adr/ADR-0008-defectdojo-bidirectional-integration.md) i [`standardem 06`](docs/standards/06-defectdojo-integration.md) ASI pełni rolę middleware: `DefectDojo ⇄ ASI ⇄ Skanery`.

- **Mapowanie:** `asset_group → Product "ASI: <nazwa>"`, `scan_run → Engagement + Test ("ASI Attack Surface Scan")`, `diff_event → Finding` (upsert po `unique_id_from_tool`, bez `reimport-scan`).
- **Push (ASI → DD):** kolejka `dd_outbox` z retry (10s/30s/2m/10m/30m); auto-push po każdym diffie (zgodnie ze `scope`) i po zakończonym runie, plus ręczny `sync`/push z UI. Endpointy: `/api/v1/integrations/defectdojo*`.
- **Pull (DD → ASI):** co `pull_interval_minutes` statusy i tagi findingów wracają do `dd_links` i na UI (SSE `defectdojo.finding_updated`).
- **Bezpieczeństwo:** API key konta „AGH” w DD tylko jako AES-256-GCM w bazie; mutacje tylko dla roli Admin (`manage_external_integrations`).
- **UI:** zakładka „Integracje (DefectDojo)” + badge `DD #id · status` na diffach.
- **Testy:** `cargo test -p asi-api --test dd_integration -- --include-ignored` (wymaga `DATABASE_URL`); lokalny DD: `docker compose -f deploy/docker-compose.dev.yml --profile dd up -d`.

## Szybki start (najprościej)

Pełna instrukcja po polsku krok po kroku: **[`docs/QUICKSTART.md`](docs/QUICKSTART.md)**.

```bash
cd /mnt/c/Users/tgarus/AGH        # ścieżka repo w WSL Ubuntu 22.04
cp -n .env.example .env           # i wpisz ASI_MASTER_KEY (openssl rand -hex 32)

make dev-up                       # terminal 0: PostgreSQL + Docker Mock-Lab
make api                          # terminal 1: API na http://127.0.0.1:8080
make ui                           # terminal 2: UI na http://localhost:5173
# terminal 3: w UI (zakładka Administracja → Tokeny workerów) wygeneruj token, potem:
export ASI_WORKER_TOKEN=<token> && make worker

make demo-scan                    # automatyczny skan mock-lab przez API (bez UI)
```

Opcjonalnie lokalny DefectDojo (Faza 6): `make dd-up && make dd-init`, konfiguracja w UI → „Integracje (DefectDojo)”.

## Weryfikacja (CI lokalnie)

```bash
make ci                           # fmt + clippy + testy + OpenAPI + UI (i18n, tsc, eslint, build)
make test-db                      # testy integracyjne na żywej bazie (wymaga: make dev-up)
```

Ręcznie, krok po kroku:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$HOME/.cache/asi-target"

cargo fmt --all -- --check && \
cargo clippy --workspace --all-targets -- -D warnings && \
cargo test --workspace && \
cargo run -p asi-api -- --export-openapi docs/openapi.json && \
cargo run -p asi-worker -- --check-capabilities && \
(cd ui && npm run gen:api && npm run check:i18n && npm run typecheck && npm run lint && npm run build)
```
