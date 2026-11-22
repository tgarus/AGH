# Standard 05: RBAC (4 role), uwierzytelnianie i bezpieczeństwo systemu

**Status:** Obowiązujący (Faza 0)  
**Data:** 2026-11-21

---

## 1. Macierz uprawnień RBAC (4 role)

Każdy endpoint publiczny `/api/v1/*` jest chroniony w `asi-api` przez warstwę ekstraktora Axum weryfikującego atomowe uprawnienia (`Permission` enum) przypisane do jednej z 4 ról:

| Obszar / Operacja | `ReadOnly` | `ReadWrite` | `ReadWriteDelete` | `Admin` |
|---|:---:|:---:|:---:|:---:|
| Podgląd dashboardu, hostów, usług, klastrów, diffów w myślnikach | Tak | Tak | Tak | Tak |
| Eksport raportów, list hostów, usług i diffów (JSON) | Tak | Tak | Tak | Tak |
| Uruchamianie (Start) i zatrzymywanie / pauza aktywnego skanu (*Kill Switch*) | Nie | Tak | Tak | Tak |
| Edycja tagów ręcznych, notatek i opisów hostów (*warstwa analityczna*) | Nie | Tak | Tak | Tak |
| Potwierdzanie / odznaczanie diffów (`acknowledge`) | Nie | Tak | Tak | Tak |
| Zarządzanie Grupami Zasobów (CRUD celów IP/CIDR/domen, wykluczeń, harmonogramów) | Nie | Nie | Tak | Tak |
| Zarządzanie politykami skanowania przypisanymi do grup *(w ramach limitów globalnych)* | Nie | Nie | Tak | Tak |
| Import celów, wykluczeń i sygnatur (JSON) | Nie | Nie | Tak | Tak |
| Usuwanie celów i lokalnych wyników skanów | Nie | Nie | Tak | Tak |
| Zarządzanie *Listą Ignorowanych* (`ignored_targets`) | Nie | Nie | Tak | Tak |
| Tworzenie, edycja i usuwanie własnych sygnatur `FingerprintHub v4` w UI | Nie | Nie | Tak | Tak |
| Wymuszenie pełnego `nmap -sV` na hoście oznaczonym `probable-tarpit` | Nie | Nie | Nie | Tak |
| Synchronizacja repozytorium `FingerprintHub` jednym kliknięciem z UI | Nie | Nie | Nie | Tak |
| Zarządzanie globalnymi limitami rate, kanałami powiadomień i sekretami webhooków | Nie | Nie | Nie | Tak |
| Rejestracja i unieważnianie tokenów `asi-worker` | Nie | Nie | Nie | Tak |
| Zarządzanie kontami użytkowników, rolami i przegląd `audit_logs` | Nie | Nie | Nie | Tak |
| Konfiguracja przyszłych integracji zewnętrznych *(np. DefectDojo w Fazie 6)* | Nie | Nie | Nie | Tak |

---

## 2. Uwierzytelnianie użytkowników (wyłącznie konta lokalne)

System nie wdraża OIDC/SSO — uwierzytelnianie opiera się wyłącznie na kontach lokalnych w PostgreSQL:

1. **Hashowanie haseł:** **`Argon2id`** z losową solą kryptograficzną per użytkownik i parametrami zgodnymi z rekomendacją OWASP (np. $m = 19\text{ MiB}$, $t = 2$, $p = 1$ lub wyższymi na serwerze docelowym).
2. **Access Token (JWT):**
   * Krótki czas życia: **`15 minut`**.
   * Algorytm podpisu: **`EdDSA` (`Ed25519`)** lub `HS256` z kluczem co najmniej 256-bitowym.
   * Przechowywany wyłącznie w pamięci aplikacji frontendowej (`asi-ui`) — zakaz zapisu JWT w `localStorage`.
3. **Rotowany Refresh Token:**
   * Losowy token o wysokiej entropii (`32 bajty` CSPRNG), ważny **`7 dni`** (konfigurowalnie).
   * Przekazywany wyłącznie jako ciasteczko **`HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth`**.
   * W bazie (`refresh_sessions`) przechowywany wyłącznie jako **hash SHA-256**.
   * **Wykrywanie ponownego użycia (*Reuse Detection*):** Próba użycia unieważnionego już Refresh Tokenu natychmiast unieważnia całą rodzinę sesji (`family_id`) danego użytkownika i rejestruje zdarzenie bezpieczeństwa w `audit_logs`.
4. **Ochrona logowania:** Limit prób logowania (*rate limit* per IP i per `username`), stałoczasowa weryfikacja w celu uniknięcia ataków czasowych przy nieistniejącym loginie oraz wymuszenie zmiany hasła startowego konta `Admin` przy pierwszym uruchomieniu.

---

## 3. Uwierzytelnianie i hartowanie węzłów skanujących (`asi-worker`)

* **Tokeny maszynowe:** Administrator generuje token rejestracyjny w `/api/v1/workers/tokens`. Serwer wyświetla surowy token **jednorazowo**, zapisując w `worker_nodes` wyłącznie jego hash SHA-256.
* **Transport:** Połączenie workera z `asi-api` zawsze przez **HTTPS/TLS 1.3** (z możliwością dodatkowego mTLS na poziomie reverse proxy w sieci produkcyjnej AGH).
* **Zasada najmniejszych uprawnień (`systemd`):**
  * `asi-worker` działa pod dedykowanym kontem systemowym bez powłoki logowania (`User=asi-worker`), **nie jako `root`**.
  * Zdolność otwierania surowych gniazd dla `naabu` / `nmap` nadawana jest precyzyjnie przez:
    `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` oraz `CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN`.
  * Hartowanie unitu: `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `ReadWritePaths=/var/lib/asi-worker`. *(Uwaga: `NoNewPrivileges=yes` musi być ustawione ostrożnie w zgodności z `AmbientCapabilities` dla procesów potomnych na docelowym jądrze Linux i przetestowane na hoście docelowym.)*

---

## 4. Ochrona danych w spoczynku i w tranzycie

| Warstwa | Mechanizm ochrony |
|---|---|
| **Wolumen bazodanowy (`PGDATA` i backupy)** | Szyfrowanie pełnodyskowe/wolumenowe **LUKS / Encryption at Rest** po stronie systemu operacyjnego. |
| **Sekrety w bazie danych (sekrety webhooków, przyszłe tokeny zewnętrzne)** | Dodatkowe szyfrowanie na poziomie aplikacji **AEAD `AES-256-GCM`** przy użyciu klucza głównego `ASI_MASTER_KEY` dostarczanego przez zmienną środowiskową / plik sekretów `systemd` (nigdy w bazie ani w repozytorium). |
| **Dane wrażliwe w wynikach skanów** | Surowe wartości nagłówków `Authorization` oraz wartości ciasteczek z celów skanowania są **odrzucane w pamięci workera przed zapisem i przed wysłaniem do `asi-api`** — w bazie lądują wyłącznie nazwy ciasteczek i ich flagi bezpieczeństwa. |
| **Komunikacja sieciowa** | **TLS 1.3** między `asi-ui` ↔ `asi-api`, `asi-worker` ↔ `asi-api` oraz `asi-api` ↔ `asi-db` (w przypadku oddzielnego hosta DB). |

---

## 5. Podwójne wymuszanie wykluczeń (*Defense in Depth*)

Aby wyeliminować ryzyko przypadkowego przeskanowania adresów chronionych lub wykluczonych:
1. **Poziom orkiestratora (`asi-api`):** Podczas tworzenia paczek (`Dynamic Micro-chunking`) i ponownie tuż przed wydaniem paczki w `/chunks/lease` odfiltrowywane są aktualne wpisy z `exclude_cidr` i `ignored_targets`.
2. **Poziom węzła (`asi-worker`):** Bezpośrednio przed uruchomieniem procesów `naabu`, `masscan`, `nmap` i klienta HTTP, worker wykonuje lokalne sprawdzenie listy celów względem dostarczonej w dzierżawie listy wykluczeń oraz blokuje próby odpytania interfejsów loopback/link-local w trybie produkcyjnym (konfigurowalnie wyłączane wyłącznie w trybie `ASI_ALLOW_LOCAL_MOCK_LAB=true` dla testów Docker Mock-Lab).
