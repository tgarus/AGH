# Standard 01: Standardy inżynieryjne, monorepo i Docker Mock-Lab

**Status:** Obowiązujący (Faza 0)  
**Data:** 2026-11-21

---

## 1. Struktura monorepo

Repozytorium utrzymywane jest jako jeden spójny monorepo łączący wspólne modele domenowe, warstwę kontrolną (`asi-api`), węzeł skanujący (`asi-worker`), interfejs webowy (`asi-ui`) oraz konfigurację wdrożeniową i testową:

```text
AGH/
├── Cargo.toml                  # Rust workspace (resolver = "2")
├── Cargo.lock
├── crates/
│   ├── asi-common/             # Wspólne modele domenowe, DTO, walidatory, OpenAPI schemas, NotificationSink
│   ├── asi-api/                # Serwer Axum, migracje SQLx, scheduler, micro-chunker, diff engine, SSE
│   └── asi-worker/             # Supervisor skanerów (Naabu/Masscan/Nmap/Rust HTTP/Nuclei), Kill Switch, klient HTTPS
├── migrations/                 # Wersjonowane migracje SQLx (PostgreSQL)
├── ui/                         # Frontend SPA (React + TypeScript + Vite + Tailwind + shadcn/ui)
│   ├── package.json
│   ├── src/
│   │   ├── api/                # Generowane typy OpenAPI (schema.d.ts) i klient HTTP
│   │   ├── i18n/               # Pliki tłumaczeń (pl/, en/)
│   │   └── ...
├── deploy/
│   ├── docker-compose.dev.yml  # PostgreSQL + asi-api + asi-ui + Docker Mock-Lab
│   ├── docker-compose.prod.yml # Warstwa zarządzania i danych dla produkcji
│   ├── mock-lab/               # Bezpieczne kontenery testowe (symulatory vhost, tarpit, flapping itp.)
│   └── systemd/                # Szablony unitów systemd dla natywnego asi-worker
├── docs/                       # Dokumentacja standaryzacyjna, ADR-y, roadmapa
└── system_architecture_attack_surface_intelligence.md
```

---

## 2. Standardy backendu (Rust)

### 2.1. Wersja języka i konfiguracja Workspace
* **Edycja i MSRV:** `edition = "2021"`, minimalna obsługiwana wersja kompilatora (MSRV): **`1.82.0`**.
* **Workspace dependencies:** Wszystkie wspólne biblioteki (`tokio`, `serde`, `serde_json`, `sqlx`, `axum`, `utoipa`, `tracing`, `thiserror`, `anyhow`, `uuid`, `chrono`, `ipnetwork`, `reqwest`) definiowane są centralnie w `[workspace.dependencies]` w głównym `Cargo.toml`.

### 2.2. Jakość kodu i obsługa błędów
* **Zero `unwrap()` / `expect()` w kodzie produkcyjnym:** Konfiguracja `[workspace.lints.clippy]` wymusza `unwrap_used = "deny"`, `expect_used = "deny"`, `panic = "deny"` (dopuszcza się wyjątki wyłącznie w `#[cfg(test)]`).
* **Obsługa błędów:**
  * Biblioteki i warstwy domenowe (`asi-common`, moduły serwisowe) używają **`thiserror`** z silnie typowanymi wariantami błędów mapowanymi na kody HTTP / RFC 9457.
  * Punkty wejścia binarek (`main.rs` w `asi-api` i `asi-worker`) mogą używać **`anyhow`** przy inicjalizacji konfiguracji.
* **Formatowanie i linting:** Obowiązkowe `cargo fmt --check` oraz `cargo clippy --workspace --all-targets -- -D warnings`.

### 2.3. Warstwa bazy danych (`sqlx`)
* Wyłącznie zapytania parametryzowane (`sqlx::query!` / `sqlx::query_as!` lub jawne bindy) — absolutny zakaz sklejania ciągów SQL.
* Każda zmiana schematu przechodzi przez wersjonowane migracje w `migrations/YYYYMMDDHHMMSS_description.sql` (migracje **forward-only** w środowiskach współdzielonych).
* Wszystkie znaczniki czasu w Rust i PostgreSQL w UTC (`chrono::DateTime<Utc>` / `TIMESTAMPTZ`).

### 2.4. Logowanie strukturalne i telemetria (`tracing`)
* Logi zapisywane w formacie JSON (`tracing_subscriber::fmt().json()`) na `stdout` (w środowisku dev dopuszczalny format czytelny przez przełącznik `ASI_LOG_FORMAT=pretty`).
* **Obowiązkowe pola korelacyjne** (gdy kontekst istnieje):
  * `request_id` (UUID v4 / v7 dla każdego żądania HTTP)
  * `user_id` (dla żądań uwierzytelnionych)
  * `scan_run_id`
  * `chunk_id`
  * `worker_id`
  * `target_ip`
* **Zakaz logowania sekretów:** Hasła, tokeny JWT, Refresh Tokeny, tokeny workerów, wartości ciasteczek z celów skanowania oraz sekrety webhooków nigdy nie mogą trafić do logów (obowiązkowe własne `Debug` z maskowaniem `[REDACTED]`).

### 2.5. OpenAPI 3.1 jako Single Source of Truth (`utoipa`)
* Każda publiczna struktura DTO (`asi-common` / `asi-api`) oraz każdy handler `/api/v1/*` musi być opisany makrami `utoipa::ToSchema` i `utoipa::path`.
* `asi-api` wystawia aktualną specyfikację pod `GET /api/v1/openapi.json` (oraz opcjonalnie CLI flagę `--export-openapi` do generowania pliku w CI bez uruchamiania bazy).

---

## 3. Standardy frontendu (`asi-ui`)

### 3.1. Stack technologiczny
* **Rdzeń:** React 18+ + TypeScript (`"strict": true`, `"noUncheckedIndexedAccess": true`) + Vite.
* **Stylowanie i komponenty:** Tailwind CSS + **shadcn/ui** (komponenty kopiowane do repozytorium, pełna kontrola dostępności i motywów).
* **Stan serwerowy i SSE:** TanStack Query (REST cache/mutacje) + dedykowany klient `EventSource` pod `/api/v1/events/stream` aktualizujący pamięć podręczną lub strumień alertów na żywo.

### 3.2. Generowanie kontraktu API (Zero ręcznych DTO)
* Zakaz ręcznego duplikowania typów API backendu w TypeScript.
* Typy w `ui/src/api/schema.d.ts` generowane są automatycznie ze schematu OpenAPI za pomocą **`openapi-typescript`** (w połączeniu z lekkim klientem `openapi-fetch`).
* W CI sprawdzana jest zgodność wygenerowanego `schema.d.ts` z aktualnym OpenAPI z `asi-api` (*OpenAPI drift check*).

### 3.3. Internacjonalizacja (`i18n`)
* Biblioteka **`react-i18next`** z przestrzeniami nazw (`common`, `dashboard`, `scans`, `hosts`, `diffs`, `policies`, `signatures`, `admin`).
* **Język domyślny:** `pl`. **Język wspierany równoważnie:** `en`.
* **Zasada kompletności:** Każdy nowy klucz tekstowy musi trafić jednocześnie do `ui/src/i18n/pl/*.json` oraz `ui/src/i18n/en/*.json`. Test w CI weryfikuje brak brakujących kluczy między językami.

### 3.4. Linting i formatowanie UI
* ESLint (reguły TypeScript strict, React Hooks, i18next literal-string check) + Prettier + `tsc --noEmit`.

### 3.5. Styl wizualny UI — utilitarny, „narzędzie sieciowe”, bez wyglądu „AI”
ASI to panel operatorski dla administratorów sieci (CBI AGH), nie strona marketingowa. Obowiązują zasady:
* **Ostre rogi, zero cieni, zero gradientów** — `--radius: 0` w `ui/src/index.css` oraz globalne wyzerowanie klas `rounded-*`/`shadow-*`; komponenty (`Card`, `Button`, `Badge`) są płaskie, obramowane (`border`), bez `bg-*/15` „świecących” kafelków.
* **Neutralna paleta dark** (szarości `hsl(0 0% …)`) + jeden akcent (bursztynowy `primary`) dla akcji głównych; statusy: zieleń/bursztyn/czerwień **tylko jako kolor tekstu + ramka**, bez półprzezroczystych teł (`bg-transparent`).
* **Gęstość i dane ponad dekorację:** bazowy `font-size: 14px`, tabele z `font-mono` dla IP/portów/ID, duże liczby KPI w `font-mono`, etykiety sekcji `uppercase tracking-wider text-xs`.
* **Brak emoji, ikon-dekoracji, animacji** — ikony tylko funkcjonalne (`lucide-react`), brak `animate-*`.
* **Nowe komponenty** budujemy na istniejących prymitywach z `ui/src/components/ui/` — nie wprowadzamy nowych efektów wizualnych ad hoc.

---

## 4. Konwencje Git i bramki CI

### 4.1. Conventional Commits
Obowiązkowy format komunikatów commitów:
* `feat(scope): ...` — nowa funkcjonalność (np. `feat(worker): implement tarpit guard threshold`)
* `fix(scope): ...` — naprawa błędu
* `docs(scope): ...` — dokumentacja / ADR
* `chore(scope): ...` / `refactor(scope): ...` / `test(scope): ...` / `ci(scope): ...`

### 4.2. Pipeline CI (minimalny zestaw bramek PR)
1. **Rust:** `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
2. **Migracje DB:** Sprawdzenie czystej aplikacji wszystkich plików z `migrations/` na instancji testowej PostgreSQL.
3. **OpenAPI Drift:** Eksport OpenAPI z `asi-api` + ponowna generacja `ui/src/api/schema.d.ts` + sprawdzenie `git diff --exit-code`.
4. **Frontend:** `npm ci`, `npm run lint`, `npm run typecheck`, weryfikacja kompletności i18n (`pl` vs `en`), `npm run build`.
5. **Bezpieczeństwo zależności:** `cargo audit` (w trybie ostrzegawczym/blokującym dla krytycznych CVE) oraz `npm audit --audit-level=high`.

---

## 5. Środowisko deweloperskie i Docker Mock-Lab

### 5.1. Zasada izolacji sieciowej
Podczas rozwoju lokalnego, testów automatycznych oraz prezentacji demonstracyjnych **bezwzględnie zabrania się** kierowania skanów w stronę produkcyjnych adresów AGH lub adresów publicznych w Internecie. Do pełnej weryfikacji potoku skanowania, diffów i obsługi anomalii służy dedykowany **Docker Mock-Lab** uruchamiany obok bazy i API (`deploy/docker-compose.dev.yml`).

### 5.2. Skład obowiązkowy Docker Mock-Lab (`deploy/mock-lab/`)
Wszystkie usługi Mock-Lab działają w wydzielonej lokalnej podsieci testowej (np. `172.28.0.0/24`) z kontrolowanymi portami i scenariuszami:

| Usługa Mock-Lab | Adres / Porty testowe | Cel weryfikacji w ASI |
|---|---|---|
| `mock-web-standard` | `80`, `443` (self-signed / test TLS) | Standardowy skan Naabu → Nmap → Rust HTTP + parser X.509 (`CN`, `SAN`, daty). |
| `mock-nonstandard-http` | `8888/tcp` (HTTP), `9443/tcp` (HTTPS) | Test reguły Artemis: wykrywanie usług webowych na niestandardowych portach i przekierowanie do Etapu 3. |
| `mock-multivhost` | `80`, `443` (2 wirtualne hosty: `app1.lab.local`, `staging.lab.local` na jednym IP) | Weryfikacja rozwiązywania Virtual Hostingu (`Host` header + `SNI`) oraz separacji obserwacji per `(ip, port, vhost)`. |
| `mock-admin-staging` | `8080/tcp` (`/admin`, `/login`, `/version`, `Set-Cookie: ADMIN_SESSION=...`, specyficzna favicona) | Test pasywnych dopasowań `FingerprintHub v4`, wykrywania paneli admina, flag ciasteczek (`HttpOnly=false`) oraz klastrowania po `MurmurHash3` favicony. |
| `mock-flapping-host` | Symulator zmieniający otwarte porty / dostępność na żądanie HTTP lub harmonogramem | Test silnika **Diff Engine**: potwierdzenie reguły progu nieaktywności ($K=3$), komunikatów *„Hej, coś się zmieniło”* vs *„Hej, coś się zmienia”* oraz budowania profilu czasowego. |
| `mock-tarpit-host` | Symulator odpowiadający `SYN-ACK` na $>250$ portach TCP | Weryfikacja **Tarpit Guard**: zapis wszystkich portów bez ucinania, oznaczenie flagą `probable-tarpit`, wstrzymanie `nmap -sV` i test ręcznego wymuszenia przez `Admina`. |

### 5.3. Konfiguracja i sekrety lokalne
* Repozytorium zawiera plik `.env.example` z wartościami testowymi i instrukcją generacji klucza `ASI_MASTER_KEY` oraz sekretu JWT.
* Rzeczywiste pliki `.env` są zawsze objęte `.gitignore` i nigdy nie są commitowane do repozytorium.
