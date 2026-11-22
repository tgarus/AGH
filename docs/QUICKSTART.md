# ASI — Szybki start (po polsku)

Attack Surface Intelligence (ASI) dla Centrum Bezpieczeństwa Informacji AGH:
cykliczne, mało inwazyjne skanowanie powierzchni ataku, Diff Engine (co się zmieniło),
Shadow IT, powiadomienia oraz dwukierunkowa integracja z DefectDojo.

Pełna architektura: [`system_architecture_attack_surface_intelligence.md`](../system_architecture_attack_surface_intelligence.md),
decyzje: [`docs/adr/`](../docs/adr/README.md), standardy: [`docs/standards/`](../docs/standards/).

---

## 0. Wymagania

| Komponent | Wymaganie |
|---|---|
| Dev (ten projekt) | Windows + **WSL2 Ubuntu 22.04** + Docker Desktop + Rust (`rustup`) + Node.js 20+ |
| Worker produkcyjny | osobny host Linux (VM/bare-metal) z `systemd`, `CAP_NET_RAW`, binarki: `nmap`, `naabu` (lub `masscan`), opcjonalnie `nuclei` |
| Baza | PostgreSQL 16 (w dev: kontener `asi-db`) |
| Przeglądarka | dowolna nowoczesna (UI jest po polsku i angielsku) |

Instalacja Rust w WSL: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` (potem `source $HOME/.cargo/bin/env`).
Node w WSL: `sudo apt install nodejs npm` lub nvm.

**Skanery na węźle workera** (produkcja): `nmap` z apt; `naabu` z release GitHub projectdiscovery; `masscan` z apt; `nuclei` opcjonalnie.
*W dev mock-lab działa też bez naabu/masscan — worker użyje wolniejszego fallbacku TCP connect (widać WARN w logu).*

## 1. Konfiguracja (raz)

```bash
cd /mnt/c/Users/tgarus/AGH          # ścieżka repo w WSL
cp .env.example .env
# Wygeneruj klucz szyfrujący sekrety (AES-256-GCM) i wpisz do .env jako ASI_MASTER_KEY:
#   openssl rand -hex 32
# Zmień też ASI_JWT_SECRET i ASI_BOOTSTRAP_ADMIN_PASSWORD.
```

## 2. Uruchomienie dev (4 terminale w WSL)

```bash
cd /mnt/c/Users/tgarus/AGH

make dev-up        # terminal 0: PostgreSQL (asi-db) + Docker Mock-Lab (cele 172.28.0.0/24)
make api           # terminal 1: asi-api na http://127.0.0.1:8080 (OpenAPI: /api/v1/openapi.json)
make ui            # terminal 2: asi-ui na http://localhost:5173 (proxy /api → 8080)
```

Worker (terminal 3) — najpierw wystaw token w UI, potem:

1. Otwórz **http://localhost:5173**, zaloguj się jako `admin` (hasło z `.env`).
2. Zakładka **Administracja i RBAC → Tokeny workerów → wygeneruj token** (rola Admin).
3. W WSL:

```bash
export ASI_WORKER_TOKEN=<token_z_UI>
# Uwaga WSL: env nie przechodzi przez `wsl` bez WSLENV, więc przy starcie spoza WSL użyj:
#   WSLENV=ASI_WORKER_TOKEN/u wsl -d Ubuntu-22.04 -- make worker
make worker        # terminal 3: asi-worker (łączy się do API po HTTP, lease'uje paczki)
```

## 3. Pierwszy skan (demo na Mock-Lab)

```bash
node scripts/demo-mock-scan.mjs     # = make demo-scan
# lub przez UI: Grupy zasobów → nowa grupa → cele: 127.0.0.1 → Skany → Start
```

Skrypt/API robi: polityka z portami mock-lab (`18080,18081,18082,18443,18444,8888,9443,19099`),
grupa, preflight (ile paczek, ETA), start skanu, a na końcu wypisuje hosty/usługi/diffy.

Gdzie patrzeć w UI (**http://localhost:5173**):

| Zakładka | Co widać |
|---|---|
| Panel główny | KPI: hosty, usługi, diffy, skany live (SSE) |
| Skany i kolejka | run'y, paczki (pending/leased/completed), pauza/stop (Hard Kill Switch ≤3 s) |
| Hosty i usługi | inventory: porty, wersje (nmap -sV), TLS, tytuły stron, technologie, tagi, notatki |
| Diffy i zmiany | „coś się zmieniło” (confirmed) vs „coś się zmienia” (wahania), bullet-changelog, acknowledge, **badge DefectDojo + przycisk „Wyślij do DD”** |
| Klastry Shadow IT | grupowanie usług po favicon/tytule/technologii |
| Sygnatury | FingerprintHub v4 (wbudowane + własne YAML + sync) |
| Powiadomienia | webhook HMAC, Slack/Teams/Mattermost/SMTP, kolejka retry |
| Integracje (DefectDojo) | konfiguracja, test połączenia, sync, kolejka outbox |
| Administracja i RBAC | użytkownicy, 4 role, tokeny workerów, audit log |

## 4. DefectDojo lokalnie (Faza 6, opcjonalnie)

```bash
make dd-up         # pobiera obraz i startuje dd-db + dd-redis + defectdojo na http://127.0.0.1:8081
make dd-init       # migracje + superuser 'agh' + wypisanie API tokena (drf_create_token)
```

Potem najprościej przez Makefile (token sam pobiera się z logu `dd-init`):

```bash
make dd-setup     # PUT konfiguracji ASI + test-connection (weryfikacja w logu)
```

albo ręcznie w UI: **Integracje (DefectDojo)** → `base_url = http://127.0.0.1:8081`, `asi_public_url = http://localhost:5173`,
**API key** (token z `make dd-init` / `make dd-token`), zakres (`changes` / `all_diffs` / `inventory`), zaznacz
`auto_push` i `enabled` → **Zapisz** → **Test połączenia** → **Synchronizuj teraz**.

Uwagi eksploatacyjne:
- obraz `defectdojo/defectdojo-django` nasłuchuje uWSGI na porcie **8081** wewnątrz kontenera (compose mapuje `127.0.0.1:8081:8081`);
- świeża baza DD nie ma typów produktów — `make dd-init` tworzy domyślny `AGH Default` (bez niego API v2 odrzuca tworzenie Product);
- token DRF w tej wersji DD wygasa domyślnie — w razie „Invalid token” wygeneruj nowy: `make dd-token`.

Od tej chwili: każdy zakończony skan publikuje diffy jako findingi w DefectDojo
(`Product = ASI: <grupa>`, `Engagement` per scan run, `Test` = „ASI Attack Surface Scan"),
a statusy ustawione w DD wracają do ASI (pull co `pull_interval` min → badge na diffach).
Szczegóły: [`docs/standards/06-defectdojo-integration.md`](standards/06-defectdojo-integration.md), [`ADR-0008`](adr/ADR-0008-defectdojo-bidirectional-integration.md).

## 5. Weryfikacja / testy

```bash
make ci            # fmt + clippy (-D warnings) + testy + OpenAPI + UI (i18n, tsc, eslint, build)
make test-db       # testy na żywej bazie (dev-up musi być włączone; używa DATABASE_URL)
```

Testy Fazy 6 (DefectDojo): `cargo test -p asi-api --test dd_integration -- --include-ignored` — mock API v2 + pełny flow na PostgreSQL.

## 6. Produkcja (skrót)

* `asi-db`: PostgreSQL na wolumenie **LUKS2** (`deploy/docker-compose.prod.yml`).
* `asi-api` + `asi-ui`: kontenery z `docker-compose.prod.yml` (TLS przed nimi — reverse proxy).
* `asi-worker`: **natywnie** jako usługa `systemd` (`deploy/systemd/asi-worker.service`, `CAP_NET_RAW`, hardening),
  binarki skanerów instalowane na hoście; worker łączy się do API po HTTPS z tokenem.
* Zmień wszystkie sekrety z `.env.example` (`ASI_JWT_SECRET`, `ASI_MASTER_KEY`, hasło admina), ustaw `ASI_COOKIE_SECURE=true`,
  `ASI_CORS_ORIGIN` na adres UI, okna czasowe w politykach skanów (Europe/Warsaw).

## 7. FAQ / rozwiązywanie problemów

| Objaw | Przyczyna / rozwiązanie |
|---|---|
| Worker loguje `naabu/masscan binary not found; using rate-limited Tokio TCP connect fallback` | Brak binarek na węźle — dev OK (wolniej); produkcja: zainstaluj `naabu`/`masscan` |
| Worker: `Invalid worker service token` | Token z UI nie dotarł do procesu — w WSL ustaw `WSLENV=ASI_WORKER_TOKEN/u` przy starcie spoza WSL; w WSL zwykły `export` wystarczy |
| Worker nie widzi sieci 172.28.0.0/24 z WSL | Docker bridge jest na hoście Windows; z WSL skanuj `127.0.0.1` (porty mock-lab są publikowane) albo wystaw workera na hoście/VM z dostępem do sieci |
| `429 Too Many Requests` przy pullu obrazów Docker Hub | Rate limit — powtórz `make dd-up` za chwilę |
| `make dd-init` nic nie robi | Entrypoint obrazu DD startuje uWSGI — używaj `exec` (tak robi Makefile) lub `docker exec asi-defectdojo ./manage.py migrate` |
| 409 `Worker node name already exists` | Nazwa workera zajęta — użyj innej nazwy w UI przy generowaniu tokena |
| API 503 `Database pool is not configured` | Brak `DATABASE_URL` — w dev: `make dev-up` i skopiowany `.env` |
| UI nie łączy się z API | Vite proxy wskazuje na `http://127.0.0.1:8080` — uruchom `make api` w tym samym WSL; z Windowsa otwórz `http://localhost:5173` |
| Po odświeżeniu strony wylatuje na login | Cookie sesji jest host-bound — zawsze używaj **jednego** adresu UI: `http://localhost:5173` (nie mieszaj z `127.0.0.1:5173`). Odświeżenie działa przez rotowany refresh-cookie; równoczesne odświeżenia są kolejkowane (single-flight) |
| Mało sygnatur w zakładce Sygnatury | `POST /api/v1/signatures/sync` (przycisk „Sync” w UI) pobiera `web-fingerprint/` z repo `0x727/FingerprintHub` (~3,5 tys. plików YAML) — dzieje się też automatycznie przy starcie API (`ASI_FINGERPRINTHUB_SYNC_ON_STARTUP=true`). Bez sieci: ustaw `ASI_FINGERPRINTHUB_LOCAL_DIR` na lokalny checkout repo |

## 8. Narzędzia dev (skrypty w `scripts/`)

| Skrypt | Do czego |
|---|---|
| `node scripts/demo-mock-scan.mjs` | pełny skan mock-labu przez API (`ASI_DEMO_GROUP_ID=<uuid>` = ten sam grupa → widać diffy; `ASI_DEMO_THRESHOLD=1` = szybciej) |
| `node scripts/dev-status.mjs [--stop]` | healthz, workery, skany, sygnatury; `--stop` zatrzymuje wiszący skan |
| `node scripts/dev-admin.mjs <cmd>` | `sync` (sygnatury z repo), `worker-token`, `dd --env`, `dd-sync`, `dd-outbox`, `dd-push <diff_id>`, `webhook`, `webhook-test <id>`, `deliveries`, `groups`, `diffs`, `scans` |
| `node scripts/dev-webhook-sink.mjs` | lokalny odbiornik webhooków na `:19999` (loguje też nagłówek `X-ASI-Signature-256`) — uruchamiaj **w WSL** (API stamtąd woła) |
| `make dd-up / dd-init / dd-token / dd-setup / dd-down` | lokalny DefectDojo: start, migracje+superuser+token+product_type, nowy token, konfiguracja ASI, stop |

## 9. Struktura repo (skrót)

```
crates/asi-common     — modele, RBAC, kontrakty (incl. DefectDojo), FingerprintHub v4
crates/asi-api        — Axum: REST /api/v1, worker API /internal/v1, orkiestrator, Diff Engine, SSE, integracje DD
crates/asi-worker     — potok 3-etapowy (Naabu/Masscan → Nmap -sV+TLS → Rust HTTP+FingerprintHub+Nuclei), Hard Kill Switch
ui/                   — React+TS+Vite, i18n pl/en, openapi-fetch z docs/openapi.json
migrations/           — SQLx (001 schema, 002 seed policy, 20261122xxx DefectDojo)
deploy/               — docker-compose.dev.yml (db+mock-lab, profil 'dd' = DefectDojo), docker-compose.prod.yml (LUKS), systemd
scripts/demo-mock-scan.mjs — demo skan mock-lab przez API
docs/                 — QUICKSTART (ten plik), standards 01–06, ADR-0001–0008, roadmap
```
