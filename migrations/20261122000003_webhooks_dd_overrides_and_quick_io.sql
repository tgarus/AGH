-- Faza 7: Subskrypcje zdarzen webhookow, modyfikacja payloadow DefectDojo i szybki import/eksport
-- 1. Subskrybowane typy zdarzen na kanalach powiadomien
ALTER TABLE notification_channels
    ADD COLUMN IF NOT EXISTS subscribed_events TEXT[] NOT NULL
    DEFAULT ARRAY['diff.confirmed_change', 'diff.active_variance']::TEXT[];

-- 2. Ogolne zdarzenia webhookow (scan.started, scan.completed, host.*, defectdojo.*, custom)
ALTER TABLE notification_deliveries
    ALTER COLUMN diff_event_id DROP NOT NULL;

ALTER TABLE notification_deliveries
    ADD COLUMN IF NOT EXISTS event_type TEXT NOT NULL DEFAULT 'diff.detected';

ALTER TABLE notification_deliveries
    ADD COLUMN IF NOT EXISTS custom_payload JSONB;

-- 3. Unikalny indeks dla bezposrednich linkow DefectDojo powiazanych z samym hostem (bez diff_event_id)
CREATE UNIQUE INDEX IF NOT EXISTS idx_dd_links_host_only
    ON dd_links (host_id)
    WHERE diff_event_id IS NULL AND host_id IS NOT NULL;
