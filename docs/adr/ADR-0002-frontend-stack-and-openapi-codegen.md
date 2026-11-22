# ADR-0002: Stack frontendu i generowanie kontraktu API z OpenAPI (`utoipa`)

* **Status:** Zaakceptowana
* **Data:** 2026-11-21
* **Powiązane dokumenty:** [`01-engineering-standards.md`](../standards/01-engineering-standards.md), [`03-api-worker-and-events.md`](../standards/03-api-worker-and-events.md)

## Kontekst
System ASI łączy zaawansowany backend w Ruście (`axum`) z panelem webowym (`asi-ui`), który musi prezentować w czasie rzeczywistym postęp skanów (SSE), rozbudowane tabele hostów, czytelne diffy w myślnikach, edytor reguł YAML oraz konfigurację polityk i uprawnień RBAC w języku polskim (z gotowością pod język angielski).

## Decyzja
1. **Stack `asi-ui`:** **React + TypeScript (`strict: true`) + Vite + Tailwind CSS + shadcn/ui + TanStack Query + `react-i18next`** (domyślny język `pl`, równoległe wsparcie `en`).
2. **Single Source of Truth dla API:** `asi-api` generuje specyfikację **OpenAPI 3.1** bezpośrednio ze struktur Rusta przy użyciu **`utoipa`**. W procesie budowania i CI frontend automatycznie generuje plik typów `ui/src/api/schema.d.ts` przy pomocy `openapi-typescript`, eliminując ręczne przepisywanie DTO.

## Konsekwencje i kompromisy
* **Pozytywne:** Szybkie dostarczanie dopracowanego UX (bogate tabele, filtry, edytor YAML, wykresy dostępności), pełne bezpieczeństwo typów między Rustem a TypeScriptem oraz natychmiastowe wykrywanie niezgodności kontraktu w CI (*OpenAPI drift check*).
* **Koszt:** Zespół musi utrzymywać dwa ekosystemy narzędziowe (Cargo dla Rusta oraz Node/npm dla Vite/React) oraz dbać o kompletność makr `utoipa::ToSchema` i plików tłumaczeń `i18n`.
