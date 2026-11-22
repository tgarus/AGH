-- ---------------------------------------------------------------------------
-- Faza 6: Dwukierunkowa integracja z DefectDojo (ADR-0008)
--
-- Model:
--   asset_group -> DefectDojo Product        (id w asset_groups.external_refs)
--   scan_run    -> DefectDojo Engagement     (id w scan_runs.external_refs)
--   scan_run    -> DefectDojo Test           (jeden test typu "ASI Attack Surface Scan")
--   diff_event  -> DefectDojo Finding        (id w dd_links, upsert po unique_id_from_tool)
--
-- Bezposrednie API v2 (create/patch finding), NIE reimport-scan — patrz ADR-0008.
-- ---------------------------------------------------------------------------

-- Haczyki na istniejacych encjach (asset_groups i hosts juz maja external_refs).
ALTER TABLE scan_runs   ADD COLUMN IF NOT EXISTS external_refs JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE diff_events ADD COLUMN IF NOT EXISTS external_refs JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Singleton konfiguracji integracji. API key tylko jako ciphertext AES-256-GCM.
CREATE TABLE defectdojo_config (
    id                    BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id = TRUE),
    base_url              TEXT NOT NULL,
    asi_public_url        TEXT NOT NULL DEFAULT '',
    api_key_ciphertext    BYTEA,
    api_key_nonce         BYTEA,
    finding_scope         TEXT NOT NULL DEFAULT 'changes'
                          CHECK (finding_scope IN ('changes', 'all_diffs', 'inventory')),
    auto_push             BOOLEAN NOT NULL DEFAULT TRUE,
    pull_interval_minutes INTEGER NOT NULL DEFAULT 15 CHECK (pull_interval_minutes BETWEEN 1 AND 1440),
    enabled               BOOLEAN NOT NULL DEFAULT FALSE,
    last_push_at          TIMESTAMPTZ,
    last_pull_at          TIMESTAMPTZ,
    last_error            TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Outbox wysyłki ASI -> DefectDojo (auto po skanie + reczny push z UI).
CREATE TABLE dd_outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind            TEXT NOT NULL CHECK (kind IN ('scan_run', 'diff_event', 'manual_sync')),
    asset_group_id  UUID NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    scan_run_id     UUID REFERENCES scan_runs(id) ON DELETE CASCADE,
    diff_event_id   UUID REFERENCES diff_events(id) ON DELETE CASCADE,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'processing', 'sent', 'failed')),
    attempt_count   INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_retry_at   TIMESTAMPTZ,
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT dd_outbox_diff_ref CHECK (
        (kind = 'diff_event' AND diff_event_id IS NOT NULL)
        OR (kind <> 'diff_event' AND diff_event_id IS NULL)
    )
);

CREATE INDEX idx_dd_outbox_due
    ON dd_outbox (next_retry_at NULLS FIRST, created_at)
    WHERE status IN ('pending', 'failed');

CREATE INDEX idx_dd_outbox_run ON dd_outbox (scan_run_id) WHERE scan_run_id IS NOT NULL;

-- Powiazania diff_event <-> obiekty DefectDojo + ostatni znany status z DD (pull).
CREATE TABLE dd_links (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    diff_event_id    UUID UNIQUE REFERENCES diff_events(id) ON DELETE CASCADE,
    host_id          UUID REFERENCES hosts(id) ON DELETE CASCADE,
    asset_group_id   UUID NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    scan_run_id      UUID REFERENCES scan_runs(id) ON DELETE SET NULL,
    dd_product_id    INTEGER,
    dd_engagement_id INTEGER,
    dd_test_id       INTEGER,
    dd_finding_id    INTEGER,
    dd_finding_status TEXT,
    dd_tags          JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_pushed_at   TIMESTAMPTZ,
    last_pulled_at   TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dd_links_finding ON dd_links (dd_finding_id) WHERE dd_finding_id IS NOT NULL;
CREATE INDEX idx_dd_links_group ON dd_links (asset_group_id, created_at DESC);
