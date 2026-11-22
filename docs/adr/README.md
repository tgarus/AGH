# Rejestr Decyzji Architektonicznych (ADR) — Attack Surface Intelligence (ASI)

Poniżej znajduje się indeks zaakceptowanych decyzji architektonicznych podjętych w **Fazie 0** standaryzacji systemu ASI.

| ID | Tytuł decyzji | Status | Data |
|---|---|---|---|
| [`ADR-0001`](ADR-0001-worker-control-plane-https-api.md) | Komunikacja `asi-worker` wyłącznie przez HTTPS API (`asi-api`) zamiast bezpośredniego dostępu do `asi-db` | Zaakceptowana | 2026-11-21 |
| [`ADR-0002`](ADR-0002-frontend-stack-and-openapi-codegen.md) | Stack frontendu (React + TypeScript + Vite + Tailwind/shadcn/ui + i18n) i generowanie typów z OpenAPI (`utoipa`) | Zaakceptowana | 2026-11-21 |
| [`ADR-0003`](ADR-0003-virtual-hosting-and-domain-targets.md) | Obsługa celów domenowych i Virtual Hostingu (rDNS + TLS SAN + nagłówek `Host` / SNI) | Zaakceptowana | 2026-11-21 |
| [`ADR-0004`](ADR-0004-fingerprinthub-v4-yaml-standard.md) | Natywny format sygnatur `FingerprintHub v4` (YAML) jako jeden standard dla Etapu 3 | Zaakceptowana | 2026-11-21 |
| [`ADR-0005`](ADR-0005-tarpit-guard-without-port-truncation.md) | Bezpiecznik *Tarpit Guard* chroniący Etap 2 bez cichego ucinania portów | Zaakceptowana | 2026-11-21 |
| [`ADR-0006`](ADR-0006-local-auth-rbac-and-secret-encryption.md) | Lokalne konta (`Argon2id` + JWT + rotowany Refresh Cookie), 4 role RBAC oraz szyfrowanie sekretów `AES-256-GCM` | Zaakceptowana | 2026-11-21 |
| [`ADR-0007`](ADR-0007-deferred-external-integrations-defectdojo.md) | Odroczenie integracji z DefectDojo do Fazy 6 na rzecz autonomicznego rdzenia *standalone* | Zaakceptowana | 2026-11-21 |
| [`ADR-0008`](ADR-0008-defectdojo-bidirectional-integration.md) | Dwukierunkowa integracja z DefectDojo (Faza 6): mapowanie `asset_group→Product`, `scan_run→Engagement+Test`, `diff_event→Finding`, bezpośrednie API v2 (bez `reimport-scan`), outbox z retry, pull statusów | Zaakceptowana | 2026-11-21 |
