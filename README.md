# Attack Surface Intelligence (ASI)

**Attack Surface Intelligence** to platforma dla **Centrum Bezpieczeństwa Informacji AGH** do automatycznego odkrywania, monitorowania i zarządzania powierzchnią ataku. System umożliwia cykliczne skanowanie infrastruktury, wykrywanie zmian (Diff Engine), identyfikację nieautoryzowanych usług (Shadow IT) oraz dwukierunkową integrację z narzędziami takimi jak DefectDojo.

## Funkcjonalności

### Skanowanie i odkrywanie
- **Port scanning**: Naabu lub Masscan z ochroną przed tarpit (Tarpit Guard)
- **Service detection**: Nmap `-sV` z parsowaniem TLS (rustls + x509-parser)
- **HTTP fingerprinting**: FingerprintHub v4 z obsługą MurmurHash3 i hot-reload sygnatur
- **rDNS/SAN**: Rozszerzone wykrywanie nazw i certyfikatów
- **Opcjonalne skanowanie luk**: Integracja z Nuclei

### Diff Engine
- Wykrywanie zmian między skanami z progowaniem nieaktywności
- Filtrowanie szumu i niestabilności w 4 slotach dobowych
- Historowana lista zmian z potwierdzeniem (acknowledge)
- Scheduler okien czasowych dla cyklicznych skanów

### Zarządzanie danymi
- **Inventory**: Hosty, porty, usługi, wersje, certyfikaty TLS, tytuły stron, technologie
- **Tagowanie i notatki**: Organizacja zasobów i dodawanie kontekstu
- **Klastry Shadow IT**: Automatyczne grupowanie usług po favicon, tytule, technologii
- **Eksport/import**: JSON schema v1.0

### Powiadomienia
- **Webhook**: HMAC-SHA256 z kolejką retry (10s, 30s, 2m, 10m, 30m)
- **Integrated platforms**: Slack, Microsoft Teams, Mattermost, SMTP
- **Szyfrowanie sekretów**: AES-256-GCM dla kluczy API i konfiguracji

### Integracje
- **DefectDojo**: Dwukierunkowa synchronizacja
  - Push: Znaleziska (findings) z ASI do DD jako Engagement + Test
  - Pull: Statusy i tagi findingów z DD z powrotem do ASI
  - Mapowanie: asset_group → Product, diff_event → Finding
  - Kolejka outbox z automatycznym retry

### API i UI
- **REST API**: OpenAPI 3.0, autoryzacja JWT, RBAC z 4 poziomami uprawnień
- **Real-time events**: Server-Sent Events (SSE) z historią i wznawianiem
- **Web UI**: React 18 + TypeScript + Tailwind CSS, obsługa PL/EN, shadcn/ui
- **Audit log**: Pełna historia działań administratorów i użytkowników

## Architektura

```
┌─────────────────────────────────────────────────────────────┐
│                        ASI UI (React)                         │
│  http://localhost:5173                                        │
└─────────────────────┬───────────────────────────────────────┘
                      │ HTTP/HTTPS
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                     ASI API (Axum + Rust)                     │
│  http://127.0.0.1:8080                                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  REST API   │  │  SSE Stream │  │  Diff Engine        │  │
│  │  (OpenAPI)  │  │  /events    │  │  + Scheduler        │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  PostgreSQL (asi-db)                                       │  │
│  │  - Hosty, usługi, skany, diffy, użytkownicy, audit log    │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────┬───────────────────────────────────────┘
                      │
    ┌─────────────────┼─────────────────┐
    ▼                 ▼                 ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  ASI Worker │ │  ASI Worker │ │  ASI Worker │
│   (Rust)    │ │   (Rust)    │ │   (Rust)    │
└─────┬───────┘ └─────┬───────┘ └─────┬───────┘
      │               │               │
      ▼               ▼               ▼
┌─────────────────────────────────────────────────────────────┐
│                    Sieć / Cele do skanowania                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ Naabu    │ │ Nmap     │ │ HTTP     │ │ Nuclei   │      │
│  │ Masscan  │ │ -sV      │ │ requests │ │ (opcj.)  │      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### Komponenty

| Komponent | Technologia | Rola |
|-----------|-------------|------|
| `asi-api` | Rust, Axum, SQLx, PostgreSQL | Serwer REST, Diff Engine, Scheduler, SSE |
| `asi-worker` | Rust, tokio, reqwest | Węzeł wykonawczy (skanowanie, fingerprinting) |
| `asi-common` | Rust | Wspólne modele, kontrakty OpenAPI, RBAC |
| `asi-ui` | React 18, TypeScript, Tailwind, shadcn/ui | Panel webowy |

## Szybki start

Pełna dokumentacja: [docs/QUICKSTART.md](docs/QUICKSTART.md)

### Wymagania

| Środowisko | Wymagania |
|------------|------------|
| **Dev** | WSL2 Ubuntu 22.04 + Docker Desktop + Rust 1.82+ + Node.js 20+ |
| **Worker (produkcja)** | Linux (VM/bare-metal) z `systemd`, `CAP_NET_RAW`, `nmap`, `naabu` lub `masscan`, opcjonalnie `nuclei` |
| **Baza danych** | PostgreSQL 16 |

### Instalacja zależności

**Rust (WSL):**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

**Node.js (WSL):**
```bash
sudo apt install nodejs npm
# lub przez nvm
```

### Konfiguracja

```bash
cd /mnt/c/Users/tgarus/AGH
cp .env.example .env
```

Edytuj `.env` i ustaw:
- `ASI_MASTER_KEY` — klucz szyfrujący (32 bajty hex): `openssl rand -hex 32`
- `ASI_JWT_SECRET` — sekret JWT (min. 32 znaki)
- `ASI_BOOTSTRAP_ADMIN_PASSWORD` — hasło dla konta admin
- `DATABASE_URL` — połączenie do PostgreSQL

### Uruchomienie (dev)

Otwórz **4 terminale w WSL**:

```bash
# Terminal 0: Baza danych + Mock-Lab (środowisko testowe)
make dev-up

# Terminal 1: API server
make api

# Terminal 2: Web UI
make ui

# Terminal 3: Worker (najpierw wygeneruj token w UI)
# 1. Otwórz http://localhost:5173, zaloguj jako admin
# 2. Administracja → Tokeny workerów → wygeneruj token (rola Admin)
# 3. W terminalu:
export ASI_WORKER_TOKEN=<token_z_UI>
make worker
```

System dostępny pod:
- **API**: http://127.0.0.1:8080
- **UI**: http://localhost:5173
- **OpenAPI**: http://127.0.0.1:8080/api/v1/openapi.json

### Pierwszy skan (demo)

```bash
# Skanowanie Docker Mock-Lab (cele 172.28.0.0/24)
make demo-scan

# lub przez UI:
# Grupy zasobów → Nowa grupa → Dodaj cele → Skany → Start
```

## Integracja z DefectDojo

### Lokalne środowisko DD (dev)

```bash
# Terminal 5: DefectDojo
make dd-up      # Start kontenerów (http://127.0.0.1:8081)
make dd-init    # Migracje + superuser 'agh' + token API

# Konfiguracja w ASI (przez UI)
# Integracje (DefectDojo) →
#   base_url: http://127.0.0.1:8081
#   api_key: <token_z_dd-init>
#   Zaznacz: enabled, auto_push
#   Zakres: changes / all_diffs / inventory
```

### Dwukierunkowa synchronizacja

- **ASI → DD**: Znaleziska (diff events) są automatycznie wysyłane jako findings
- **DD → ASI**: Statusy i tagi findingów wracają do ASI i są widoczne w UI
- **Mapowanie**: `asset_group` → `Product`, `scan_run` → `Engagement + Test`

## Konfiguracja produkcji

### Docker Compose

```bash
# Produkcja z LUKS dla PGDATA
cp .env.example .env
# Edytuj .env dla środowiska produkcyjnego
docker compose -f deploy/docker-compose.prod.yml up -d
```

### systemd

Gotowe unit-y systemd dostępne w `deploy/systemd/`.

### Węzeł worker

Produkcyjny worker wymaga:
- System Linux z `CAP_NET_RAW`
- Zainstalowane narzędzia: `nmap`, `naabu` lub `masscan`
- Konfiguracja w `.env`:
  ```bash
  ASI_WORKER_API_URL=https://asi-api.example.com
  ASI_WORKER_TOKEN=<token_z_UI>
  ASI_WORKER_NAME=production-worker-01
  ASI_WORKER_SEGMENT_TAG=production
  ```

## Powiadomienia

Konfiguracja w UI: **Powiadomienia → Nowy endpoint**

| Typ | Obsługiwane | Sekrety |
|-----|-------------|---------|
| Webhook | JSON payload | HMAC-SHA256 (opcjonalnie) |
| Slack | #channel lub @user | Token Bot |
| Microsoft Teams | Webhook URL | - |
| Mattermost | Webhook URL | - |
| SMTP | Email | Login/hasło, STARTTLS |

Wszystkie powiadomienia obsługują kolejkę retry z opóźnieniami: 10s, 30s, 2m, 10m, 30m.

## RBAC (Role-Based Access Control)

| Rola | Uprawnienia |
|------|-------------|
| **Admin** | Pełny dostęp: zarządzanie użytkownikami, tokeny workerów, integracje, konfiguracja systemu |
| **Security** | Przeglądanie i zarządzanie: skany, hosty, usługi, diffy, Shadow IT |
| **Auditor** | Tylko odczyt: widok inventory, diffów, raportów |
| **Viewer** | Ograniczone dane: podstawowe KPI, podsumowania |

## Weryfikacja i CI

### Lokalne testy

```bash
# Formatowanie, linting, testy
make ci

# Testy integracyjne (wymaga uruchomionego dev-up)
make test-db

# Ręczne sprawdzenie
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

### Skrypty diagnostyczne

```bash
# Test API (smoke test)
./smoke_api.sh

# Diagnostyka DefectDojo
make dd-self-test
make dd-inspect
```

## Struktura projektu

```text
AGH/
├── crates/
│   ├── asi-api/       # Serwer REST (Axum + SQLx + PostgreSQL)
│   ├── asi-worker/     # Węzeł wykonawczy (skanowanie)
│   └── asi-common/     # Wspólne modele, kontrakty, RBAC
├── ui/                # Panel webowy (React + TypeScript)
├── deploy/
│   ├── docker-compose.dev.yml   # Dev: PostgreSQL + Mock-Lab
│   ├── docker-compose.prod.yml  # Produkcja z LUKS
│   ├── systemd/        # Unit-y systemd
│   └── mock-lab/       # Konfiguracja środowiska testowego
├── docs/
│   ├── adr/            # Architecture Decision Records
│   ├── standards/      # Standardy i procedury
│   └── QUICKSTART.md   # Przewodnik szybkiego startu
├── migrations/        # Migracje bazy danych
├── scripts/           # Skrypty pomocnicze
├── Cargo.toml         # Workspace Rust
├── Makefile           # Komendy developmentowe
└── README.md
```

## Licencja

MIT License — patrz [LICENSE](LICENSE) lub nagłówek w plikach źródłowych.

---

**Autor**: AGH Information Security Center  
**Wersja**: 0.1.0  
**Język**: Rust 1.82+, React 18, TypeScript 5
