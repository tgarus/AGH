-- Phase 1 Initial PostgreSQL Schema for Attack Surface Intelligence (ASI)
-- Aligned with docs/standards/02-domain-and-data-model.md

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- 1. Identity, Sessions & Worker Nodes
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username         TEXT UNIQUE NOT NULL,
    email            TEXT UNIQUE NOT NULL,
    password_hash    TEXT NOT NULL,
    role             TEXT NOT NULL CHECK (role IN ('Admin', 'ReadWriteDelete', 'ReadWrite', 'ReadOnly')),
    is_active        BOOLEAN NOT NULL DEFAULT TRUE,
    preferred_locale TEXT NOT NULL DEFAULT 'pl',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at    TIMESTAMPTZ
);

CREATE TABLE refresh_sessions (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id      UUID NOT NULL,
    token_hash     TEXT UNIQUE NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    revoked_at     TIMESTAMPTZ,
    replaced_by_id UUID REFERENCES refresh_sessions(id) ON DELETE SET NULL,
    created_ip     INET,
    user_agent     TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_sessions_user ON refresh_sessions (user_id);
CREATE INDEX idx_refresh_sessions_family ON refresh_sessions (family_id);
CREATE INDEX idx_refresh_sessions_expires ON refresh_sessions (expires_at);

CREATE TABLE worker_nodes (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name              TEXT UNIQUE NOT NULL,
    segment_tag       TEXT,
    token_hash        TEXT UNIQUE NOT NULL,
    status            TEXT NOT NULL CHECK (status IN ('online', 'offline', 'draining', 'revoked')),
    capabilities      JSONB NOT NULL DEFAULT '{}'::jsonb,
    max_concurrency   INTEGER NOT NULL DEFAULT 1 CHECK (max_concurrency >= 1),
    last_heartbeat_at TIMESTAMPTZ,
    registered_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at        TIMESTAMPTZ
);

-- ---------------------------------------------------------------------------
-- 2. Scan Policies, Asset Groups & Ignored Targets
-- ---------------------------------------------------------------------------

CREATE TABLE scan_policies (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  TEXT UNIQUE NOT NULL,
    port_spec             TEXT NOT NULL,
    discovery_tool        TEXT NOT NULL CHECK (discovery_tool IN ('naabu', 'masscan')),
    rate_pps              INTEGER NOT NULL CHECK (rate_pps > 0),
    per_ip_cooldown_ms    INTEGER NOT NULL CHECK (per_ip_cooldown_ms >= 0),
    subnet_concurrency    INTEGER NOT NULL CHECK (subnet_concurrency > 0),
    kill_grace_seconds    INTEGER NOT NULL DEFAULT 3 CHECK (kill_grace_seconds BETWEEN 1 AND 10),
    inactivity_threshold  INTEGER NOT NULL DEFAULT 3 CHECK (inactivity_threshold >= 1),
    tarpit_port_threshold INTEGER NOT NULL DEFAULT 200 CHECK (tarpit_port_threshold >= 1),
    enable_nuclei         BOOLEAN NOT NULL DEFAULT FALSE,
    time_windows          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE asset_groups (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             TEXT UNIQUE NOT NULL,
    description      TEXT,
    policy_id        UUID NOT NULL REFERENCES scan_policies(id) ON DELETE RESTRICT,
    schedule_cron    TEXT,
    sampling_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    external_refs    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_asset_groups_external_refs ON asset_groups USING GIN (external_refs);

CREATE TABLE asset_group_targets (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_group_id UUID NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    target_type    TEXT NOT NULL CHECK (target_type IN ('ip', 'cidr', 'domain', 'exclude_cidr')),
    value          TEXT NOT NULL,
    notes          TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (asset_group_id, target_type, value)
);

CREATE TABLE ignored_targets (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_group_id UUID REFERENCES asset_groups(id) ON DELETE CASCADE,
    target_type    TEXT NOT NULL CHECK (target_type IN ('ip', 'cidr', 'domain')),
    value          TEXT NOT NULL,
    reason         TEXT NOT NULL,
    created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_ignored_targets_unique_scope
    ON ignored_targets (COALESCE(asset_group_id, '00000000-0000-0000-0000-000000000000'::uuid), target_type, value);

-- ---------------------------------------------------------------------------
-- 3. Orchestration, Micro-chunk Queue & Per-IP Locks
-- ---------------------------------------------------------------------------

CREATE TABLE scan_runs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_group_id      UUID NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    policy_snapshot     JSONB NOT NULL,
    trigger_type        TEXT NOT NULL CHECK (trigger_type IN ('manual', 'scheduled', 'sampling')),
    time_slot           TEXT CHECK (time_slot IN ('00_06', '06_12', '12_18', '18_24')),
    status              TEXT NOT NULL CHECK (status IN ('queued', 'running', 'pausing', 'paused', 'stopping', 'stopped', 'completed', 'failed')),
    total_targets       INTEGER NOT NULL CHECK (total_targets >= 0),
    total_chunks        INTEGER NOT NULL CHECK (total_chunks >= 0),
    completed_chunks    INTEGER NOT NULL DEFAULT 0 CHECK (completed_chunks >= 0),
    ema_chunk_ms        DOUBLE PRECISION,
    estimated_finish_at TIMESTAMPTZ,
    started_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at         TIMESTAMPTZ,
    cancel_requested_at TIMESTAMPTZ
);

CREATE INDEX idx_scan_runs_group_status ON scan_runs (asset_group_id, status);

CREATE TABLE scan_chunks (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id         UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    sequence_no         INTEGER NOT NULL,
    subnet_bucket       TEXT NOT NULL,
    targets             JSONB NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('pending', 'leased', 'completed', 'failed', 'cancelled')),
    attempt_no          INTEGER NOT NULL DEFAULT 0 CHECK (attempt_no >= 0),
    leased_by_worker_id UUID REFERENCES worker_nodes(id) ON DELETE SET NULL,
    lease_expires_at    TIMESTAMPTZ,
    last_heartbeat_at   TIMESTAMPTZ,
    duration_ms         INTEGER,
    error_message       TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,
    UNIQUE (scan_run_id, sequence_no)
);

CREATE INDEX idx_scan_chunks_queue
    ON scan_chunks (scan_run_id, sequence_no)
    WHERE status = 'pending';

CREATE INDEX idx_scan_chunks_leased
    ON scan_chunks (status, lease_expires_at)
    WHERE status = 'leased';

CREATE TABLE ip_locks (
    ip_addr             INET PRIMARY KEY,
    locked_by_chunk_id  UUID NOT NULL REFERENCES scan_chunks(id) ON DELETE CASCADE,
    locked_by_worker_id UUID NOT NULL REFERENCES worker_nodes(id) ON DELETE CASCADE,
    locked_until        TIMESTAMPTZ NOT NULL,
    cooldown_until      TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_ip_locks_expiry ON ip_locks (locked_until, cooldown_until);

-- ---------------------------------------------------------------------------
-- 4. Inventory: Hosts, Hostnames, Ports, TLS & Web Observations
--    (Strict Scan-First Truth separation between technical and analytical columns)
-- ---------------------------------------------------------------------------

CREATE TABLE hosts (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_group_id           UUID NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    ip_addr                  INET NOT NULL,

    -- Technical columns (overwritten by scan engine, audited on change)
    status                   TEXT NOT NULL CHECK (status IN ('active', 'missing_pending', 'inactive', 'ignored')),
    consecutive_misses       INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_misses >= 0),
    is_unstable              BOOLEAN NOT NULL DEFAULT FALSE,
    is_probable_tarpit       BOOLEAN NOT NULL DEFAULT FALSE,
    availability_profile     JSONB NOT NULL DEFAULT '{}'::jsonb,
    auto_tags                TEXT[] NOT NULL DEFAULT '{}',
    first_seen_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at             TIMESTAMPTZ,
    last_scanned_at          TIMESTAMPTZ,

    -- Analytical columns (never overwritten by scan engine)
    manual_tags              TEXT[] NOT NULL DEFAULT '{}',
    notes                    TEXT,
    owner_hint               TEXT,
    tarpit_override_force_sv BOOLEAN NOT NULL DEFAULT FALSE,
    tarpit_override_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    tarpit_override_at       TIMESTAMPTZ,
    external_refs            JSONB NOT NULL DEFAULT '{}'::jsonb,

    UNIQUE (asset_group_id, ip_addr)
);

CREATE INDEX idx_hosts_auto_tags ON hosts USING GIN (auto_tags);
CREATE INDEX idx_hosts_manual_tags ON hosts USING GIN (manual_tags);
CREATE INDEX idx_hosts_external_refs ON hosts USING GIN (external_refs);

CREATE TABLE host_hostnames (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id       UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    hostname      TEXT NOT NULL,
    source        TEXT NOT NULL CHECK (source IN ('user_input', 'rdns', 'tls_san')),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (host_id, hostname)
);

CREATE TABLE host_ports (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id            UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port               INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol           TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    state              TEXT NOT NULL CHECK (state IN ('active', 'missing_pending', 'closed')),
    consecutive_misses INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_misses >= 0),
    service_name       TEXT,
    product            TEXT,
    version            TEXT,
    extra_info         TEXT,
    is_web_candidate   BOOLEAN NOT NULL DEFAULT FALSE,
    tunnel             TEXT,
    raw_banner         TEXT,
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (host_id, port, protocol)
);

CREATE INDEX idx_host_ports_web_candidates
    ON host_ports (host_id, is_web_candidate)
    WHERE is_web_candidate = TRUE;

CREATE TABLE tls_certificates (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_port_id       UUID UNIQUE NOT NULL REFERENCES host_ports(id) ON DELETE CASCADE,
    sha256_fingerprint TEXT NOT NULL,
    subject_cn         TEXT,
    issuer_cn          TEXT,
    san_dns            TEXT[] NOT NULL DEFAULT '{}',
    not_before         TIMESTAMPTZ,
    not_after          TIMESTAMPTZ,
    is_self_signed     BOOLEAN NOT NULL DEFAULT FALSE,
    observed_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE web_observations (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_port_id         UUID NOT NULL REFERENCES host_ports(id) ON DELETE CASCADE,
    vhost                TEXT NOT NULL,
    scheme               TEXT NOT NULL CHECK (scheme IN ('http', 'https')),
    http_status          INTEGER,
    final_url            TEXT,
    redirect_target      TEXT,
    title                TEXT,
    headers_filtered     JSONB NOT NULL DEFAULT '{}'::jsonb,
    cookies_meta         JSONB NOT NULL DEFAULT '[]'::jsonb,
    favicon_mmh3         BIGINT,
    matched_technologies JSONB NOT NULL DEFAULT '[]'::jsonb,
    detected_paths       TEXT[] NOT NULL DEFAULT '{}',
    last_observed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (host_port_id, vhost, scheme)
);

CREATE INDEX idx_web_observations_favicon
    ON web_observations (favicon_mmh3)
    WHERE favicon_mmh3 IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 5. Availability Sampling, Diffs, Signatures, Notifications & Audit
-- ---------------------------------------------------------------------------

CREATE TABLE host_availability_samples (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    scan_run_id     UUID REFERENCES scan_runs(id) ON DELETE SET NULL,
    time_slot       TEXT NOT NULL CHECK (time_slot IN ('00_06', '06_12', '12_18', '18_24')),
    is_alive        BOOLEAN NOT NULL,
    open_ports_hash TEXT NOT NULL,
    sampled_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_host_availability_samples_host
    ON host_availability_samples (host_id, sampled_at DESC);

CREATE TABLE diff_events (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id           UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    scan_run_id       UUID REFERENCES scan_runs(id) ON DELETE SET NULL,
    event_kind        TEXT NOT NULL CHECK (event_kind IN ('confirmed_change', 'active_variance')),
    severity          TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high')),
    bullet_items      JSONB NOT NULL,
    previous_snapshot JSONB,
    current_snapshot  JSONB,
    acknowledged_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at   TIMESTAMPTZ,
    detected_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_diff_events_detected_at ON diff_events (detected_at DESC);
CREATE INDEX idx_diff_events_host_detected ON diff_events (host_id, detected_at DESC);

CREATE TABLE signature_rules (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id    TEXT UNIQUE NOT NULL,
    name           TEXT NOT NULL,
    source         TEXT NOT NULL CHECK (source IN ('fingerprinthub', 'custom')),
    format         TEXT NOT NULL DEFAULT 'fingerprinthub_v4_yaml',
    yaml_content   TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    tags           TEXT[] NOT NULL DEFAULT '{}',
    is_enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    synced_at      TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE notification_channels (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT UNIQUE NOT NULL,
    channel_type        TEXT NOT NULL CHECK (channel_type IN ('webhook_json', 'slack', 'teams', 'mattermost', 'smtp')),
    asset_group_id      UUID REFERENCES asset_groups(id) ON DELETE CASCADE,
    notify_on_confirmed BOOLEAN NOT NULL DEFAULT TRUE,
    notify_on_variance  BOOLEAN NOT NULL DEFAULT TRUE,
    config_public       JSONB NOT NULL DEFAULT '{}'::jsonb,
    secret_ciphertext   BYTEA,
    secret_nonce        BYTEA,
    is_enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE notification_deliveries (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id    UUID NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    diff_event_id UUID NOT NULL REFERENCES diff_events(id) ON DELETE CASCADE,
    status        TEXT NOT NULL CHECK (status IN ('pending', 'sent', 'failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_retry_at TIMESTAMPTZ,
    last_error    TEXT,
    sent_at       TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notification_deliveries_pending
    ON notification_deliveries (status, next_retry_at)
    WHERE status = 'pending';

CREATE TABLE audit_logs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_type    TEXT NOT NULL CHECK (actor_type IN ('user', 'scan_engine', 'system')),
    actor_id      UUID,
    action        TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id   UUID,
    before_state  JSONB,
    after_state   JSONB,
    source_ip     INET,
    request_id    UUID,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at DESC);
CREATE INDEX idx_audit_logs_resource ON audit_logs (resource_type, resource_id);
