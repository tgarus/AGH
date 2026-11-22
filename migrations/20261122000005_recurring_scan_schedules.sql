CREATE TABLE IF NOT EXISTS recurring_scan_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_group_id UUID NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    interval_value INTEGER NOT NULL CHECK (interval_value >= 1),
    interval_unit TEXT NOT NULL CHECK (interval_unit IN ('minutes', 'hours')),
    first_run_time TEXT NOT NULL DEFAULT '00:00',
    window_minutes INTEGER NOT NULL DEFAULT 120 CHECK (window_minutes >= 5 AND window_minutes <= 1440),
    include_all_ignored BOOLEAN NOT NULL DEFAULT FALSE,
    include_ignored_ids UUID[] NOT NULL DEFAULT '{}',
    last_run_at TIMESTAMPTZ,
    last_scan_run_id UUID REFERENCES scan_runs(id) ON DELETE SET NULL,
    next_run_at TIMESTAMPTZ NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_recurring_scan_schedules_next_run
    ON recurring_scan_schedules(next_run_at ASC);
CREATE INDEX IF NOT EXISTS idx_recurring_scan_schedules_group
    ON recurring_scan_schedules(asset_group_id);
