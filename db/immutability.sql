-- ══════════════════════════════════════════════════════════════════════════
--  Audit Log Immutability & Hash Chain
--  Run from shadow-it-detection/ :
--    psql -U postgres -d shadow_it_db -f db/immutability.sql
-- ══════════════════════════════════════════════════════════════════════════

-- ── 1. pgcrypto (needed for SHA-256 inside the DB) ────────────────────────
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── 2. Hash column on audit_logs ──────────────────────────────────────────
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS entry_hash CHAR(64);

-- ── 3. BEFORE INSERT trigger — auto-computes SHA-256 hash chain ───────────
CREATE OR REPLACE FUNCTION fn_audit_hash()
RETURNS TRIGGER AS $$
DECLARE
  prev_hash TEXT;
  content   TEXT;
BEGIN
  -- get the most recent hash (or all-zeros genesis for first entry)
  SELECT COALESCE(entry_hash, repeat('0', 64))
  INTO   prev_hash
  FROM   audit_logs
  ORDER  BY id DESC
  LIMIT  1;

  content :=
      NEW.user_id::TEXT                        || '|' ||
      NEW.action                               || '|' ||
      COALESCE(NEW.target,     '')             || '|' ||
      COALESCE(NEW.ip_address, '')             || '|' ||
      NEW.timestamp::TEXT                      || '|' ||
      COALESCE(prev_hash, repeat('0', 64));

  NEW.entry_hash := encode(digest(content, 'sha256'), 'hex');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_hash ON audit_logs;
CREATE TRIGGER trg_audit_hash
  BEFORE INSERT ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION fn_audit_hash();

-- ── 4. BEFORE UPDATE / DELETE triggers — hard block ───────────────────────
CREATE OR REPLACE FUNCTION fn_audit_immutable()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION
    'Audit log entries are immutable — modifications are not permitted.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_no_update ON audit_logs;
CREATE TRIGGER trg_audit_no_update
  BEFORE UPDATE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION fn_audit_immutable();

DROP TRIGGER IF EXISTS trg_audit_no_delete ON audit_logs;
CREATE TRIGGER trg_audit_no_delete
  BEFORE DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION fn_audit_immutable();

-- ── 5. Detection log immutability ──────────────────────────────────────────
-- Scan results (live capture + dataset runs) are a record of what was
-- actually detected -- same tamper-proofing rationale as audit_logs, but
-- detections has one legitimate write path (the Resolve button, which only
-- ever sets is_resolved), so this blocks DELETE entirely and blocks UPDATE
-- of every column except is_resolved, rather than blocking UPDATE outright.
CREATE OR REPLACE FUNCTION fn_detections_no_delete()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION
    'Detection records are immutable — deleting scan logs is not permitted.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_detections_no_delete ON detections;
CREATE TRIGGER trg_detections_no_delete
  BEFORE DELETE ON detections
  FOR EACH ROW EXECUTE FUNCTION fn_detections_no_delete();

CREATE OR REPLACE FUNCTION fn_detections_guard_update()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.id             IS DISTINCT FROM OLD.id             OR
     NEW.src_ip          IS DISTINCT FROM OLD.src_ip         OR
     NEW.src_mac         IS DISTINCT FROM OLD.src_mac        OR
     NEW.dst_domain      IS DISTINCT FROM OLD.dst_domain     OR
     NEW.protocol        IS DISTINCT FROM OLD.protocol       OR
     NEW.bytes_sent      IS DISTINCT FROM OLD.bytes_sent     OR
     NEW.bytes_received  IS DISTINCT FROM OLD.bytes_received OR
     NEW.duration        IS DISTINCT FROM OLD.duration       OR
     NEW.device_type     IS DISTINCT FROM OLD.device_type    OR
     NEW.shadow_it_type  IS DISTINCT FROM OLD.shadow_it_type OR
     NEW.risk_level      IS DISTINCT FROM OLD.risk_level     OR
     NEW.anomaly_score   IS DISTINCT FROM OLD.anomaly_score  OR
     NEW.detected_at     IS DISTINCT FROM OLD.detected_at    OR
     NEW.source          IS DISTINCT FROM OLD.source THEN
    RAISE EXCEPTION
      'Detection records are immutable — only is_resolved may be updated.';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_detections_guard_update ON detections;
CREATE TRIGGER trg_detections_guard_update
  BEFORE UPDATE ON detections
  FOR EACH ROW EXECUTE FUNCTION fn_detections_guard_update();

-- ── 6. Restricted application role (INSERT + SELECT only on audit_logs) ───
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shadow_it_app') THEN
    CREATE ROLE shadow_it_app WITH LOGIN PASSWORD 'sh4d0w_app_2026';
  END IF;
END $$;

GRANT CONNECT  ON DATABASE shadow_it_db TO shadow_it_app;
GRANT USAGE    ON SCHEMA  public        TO shadow_it_app;

-- detections: insert (new scans) + select + update (Resolve button only,
-- enforced by trg_detections_guard_update above) -- no DELETE grant, and the
-- trigger blocks it at the database level regardless of role anyway. Explicit
-- REVOKE so re-running this file on a DB provisioned by the old version (which
-- granted DELETE) actually strips it, instead of the additive GRANT below
-- silently leaving the old DELETE grant in place.
REVOKE DELETE ON detections FROM shadow_it_app;
GRANT SELECT, INSERT, UPDATE ON detections TO shadow_it_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON users TO shadow_it_app;

-- Audit logs: append + read only — NO UPDATE, NO DELETE
GRANT SELECT, INSERT ON audit_logs TO shadow_it_app;

-- Token denylist: read/insert (logout revocation) + delete (expiry cleanup)
GRANT SELECT, INSERT, DELETE ON token_denylist TO shadow_it_app;

-- Device sightings: first-seen registry, upserted on every new device
GRANT SELECT, INSERT, UPDATE ON device_sightings TO shadow_it_app;

-- Sequences
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO shadow_it_app;
