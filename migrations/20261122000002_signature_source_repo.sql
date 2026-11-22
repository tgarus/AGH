-- Allow signature rules synced from the upstream FingerprintHub GitHub repo
-- (in addition to built-ins and custom rules).
ALTER TABLE signature_rules
    DROP CONSTRAINT IF EXISTS signature_rules_source_check;

ALTER TABLE signature_rules
    ADD CONSTRAINT signature_rules_source_check
    CHECK (source IN ('fingerprinthub', 'fingerprinthub_repo', 'custom'));
