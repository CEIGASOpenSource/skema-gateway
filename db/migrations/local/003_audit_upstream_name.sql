-- 003_audit_upstream_name — track which tile/upstream a call routed through.
--
-- Routing metadata, not a security-critical field. Deliberately NOT included
-- in the HMAC chain in audit.py: tampering with this column can mislead the
-- UI but cannot forge an operator/entity/action record (those remain signed).
--
-- NULL on rows inserted before this migration; new rows set it from the
-- gateway's active-upstream selection at the moment of the call.

ALTER TABLE operator_audit_log
    ADD COLUMN IF NOT EXISTS upstream_name TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_upstream
    ON operator_audit_log(upstream_name, occurred_at DESC)
    WHERE upstream_name IS NOT NULL;
