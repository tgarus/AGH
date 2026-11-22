-- Batch 2: Asset group member scoping, worker node visibility/scoping,
-- per-scan ignored-targets overrides, and host/service comments.

-- 1. Asset group user membership (many-to-many)
CREATE TABLE IF NOT EXISTS asset_group_members (
    asset_group_id UUID NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (asset_group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_asset_group_members_user ON asset_group_members(user_id);

-- 2. Scanning node (worker_nodes) visibility/scoping
ALTER TABLE worker_nodes
    ADD COLUMN IF NOT EXISTS visibility_scope TEXT NOT NULL DEFAULT 'all'
        CHECK (visibility_scope IN ('all', 'restricted')),
    ADD COLUMN IF NOT EXISTS allowed_asset_group_ids UUID[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS allowed_user_ids UUID[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id) ON DELETE SET NULL;

-- 3. Per-scan ignored-targets override on scan_runs
ALTER TABLE scan_runs
    ADD COLUMN IF NOT EXISTS include_all_ignored BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS overridden_ignored_values TEXT[] NOT NULL DEFAULT '{}';

-- 4. Host and service/port comments
CREATE TABLE IF NOT EXISTS host_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    host_port_id UUID REFERENCES host_ports(id) ON DELETE CASCADE,
    port INTEGER,
    protocol TEXT,
    author_id UUID REFERENCES users(id) ON DELETE SET NULL,
    author_name TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_host_comments_host_id ON host_comments(host_id, created_at DESC);
