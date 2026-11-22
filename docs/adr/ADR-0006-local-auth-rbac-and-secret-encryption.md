# ADR-0006: Lokalne uwierzytelnianie, RBAC (4 role) oraz szyfrowanie sekretów w bazie

* **Status:** Zaakceptowana
* **Data:** 2026-11-21
* **Powiązane dokumenty:** [`02-domain-and-data-model.md`](../standards/02-domain-and-data-model.md), [`05-rbac-and-security.md`](../standards/05-rbac-and-security.md)

## Kontekst
System wymaga bezpiecznego modelu dostępu opartego na 4 rolach RBAC (`Admin`, `ReadWriteDelete`, `ReadWrite`, `ReadOnly`), bez nadmiarowej złożoności integracji z zewnętrznymi dostawcami tożsamości (OIDC/SSO) na etapie budowy rdzenia, przy jednoczesnym zachowaniu wysokiego standardu ochrony sesji oraz sekretów przechowywanych w bazie danych (sekrety webhooków, przyszłe tokeny integracji).

## Decyzja
1. **Wyłącznie konta lokalne (bez OIDC/SSO):** Użytkownicy uwierzytelniani są lokalnie względem tabeli `users` z hasłami hashowanymi algorytmem **`Argon2id`**.
2. **Hybrydowy model sesji (JWT + rotowany Refresh Cookie):**
   * Krótkotrwały **Access Token JWT** (`15 min`) przechowywany wyłącznie w pamięci przeglądarki.
   * **Refresh Token** (`7 dni`) w ciasteczku `HttpOnly; Secure; SameSite=Strict`, rotowany przy każdym odświeżeniu, z detekcją ponownego użycia i unieważnianiem całej rodziny sesji w `refresh_sessions`.
3. **RBAC:** 4 role egzekwowane w `asi-api` przez ekstraktory oparte na atomowym enumie `Permission`.
4. **Szyfrowanie warstwowe (*Defense in Depth*):** Oprócz szyfrowania wolumenu `PGDATA` (LUKS), wszystkie wrażliwe sekrety aplikacyjne w PostgreSQL są szyfrowane warstwowo algorytmem **AEAD `AES-256-GCM`** przy użyciu klucza głównego `ASI_MASTER_KEY`.

## Konsekwencje i kompromisy
* **Pozytywne:** Szybkie, niezależne wdrożenie bez zależności od zewnętrznego IdP, brak podatności na wykradzenie długowiecznych tokenów z `localStorage`, natychmiastowa możliwość unieważniania sesji oraz pełna ochrona sekretów webhooków nawet przy wycieku samego dumpa SQL.
* **Koszt:** Zarządzanie kontami i resetem haseł spoczywa na administratorze ASI; utrata `ASI_MASTER_KEY` uniemożliwia odszyfrowanie sekretów webhooków w DB (wymagana procedura backupu klucza).
