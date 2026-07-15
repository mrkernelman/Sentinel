import os
import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv

load_dotenv()


def get_connection():
    return psycopg.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", 5432)),
        dbname=os.getenv("DB_NAME", "shadow_it_db"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
    )


def ensure_auth_schema():
    """Ensure the JWT revocation (denylist) table exists. Fresh Docker
    volumes get it from schema.sql; this is a fallback for databases created
    before it was added. Checks existence first so it's a safe no-op under
    the restricted role (which has USAGE but not CREATE on the schema)."""
    exists = execute(
        "SELECT 1 AS x FROM information_schema.tables WHERE table_name = 'token_denylist'",
        fetch="one",
    )
    if not exists:
        execute(
            """CREATE TABLE token_denylist (
                   jti        TEXT PRIMARY KEY,
                   expires_at TIMESTAMPTZ NOT NULL
               )"""
        )


def ensure_detections_source_column():
    """Ensure detections.source exists (distinguishes 'live' scan rows from
    'dataset' /api/run-detection rows). Fresh Docker volumes get it from
    schema.sql; this is a fallback for databases created before it was
    added. Checks existence first for the same reason as ensure_auth_schema()
    -- safe no-op under the restricted role once the column exists."""
    exists = execute(
        "SELECT 1 AS x FROM information_schema.columns "
        "WHERE table_name = 'detections' AND column_name = 'source'",
        fetch="one",
    )
    if not exists:
        execute(
            "ALTER TABLE detections ADD COLUMN source VARCHAR(10) NOT NULL DEFAULT 'dataset'"
        )
        execute("CREATE INDEX IF NOT EXISTS idx_detections_source ON detections(source)")


def ensure_device_sightings_schema():
    """Ensure device_sightings exists. Fresh Docker volumes get it from
    schema.sql; this is a fallback for databases created before it was
    added. Same existence-check-first idiom as ensure_auth_schema()."""
    exists = execute(
        "SELECT 1 AS x FROM information_schema.tables WHERE table_name = 'device_sightings'",
        fetch="one",
    )
    if not exists:
        execute(
            """CREATE TABLE device_sightings (
                   id               SERIAL PRIMARY KEY,
                   src_ip           VARCHAR(45) NOT NULL,
                   src_mac          VARCHAR(17),
                   source           VARCHAR(10) NOT NULL DEFAULT 'live',
                   first_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                   last_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                   sightings_count  INTEGER NOT NULL DEFAULT 1,
                   UNIQUE (src_ip, src_mac)
               )"""
        )
        execute("CREATE INDEX IF NOT EXISTS idx_device_sightings_last_seen ON device_sightings(last_seen DESC)")


def ensure_known_assets_schema():
    """Ensure known_devices / known_applications exist. Fresh Docker volumes
    get them from schema.sql; this is a fallback for databases created
    before they were added. Same existence-check-first idiom as
    ensure_auth_schema()."""
    exists = execute(
        "SELECT 1 AS x FROM information_schema.tables WHERE table_name = 'known_devices'",
        fetch="one",
    )
    if not exists:
        execute(
            """CREATE TABLE known_devices (
                   id          SERIAL PRIMARY KEY,
                   src_ip      VARCHAR(45),
                   src_mac     VARCHAR(17),
                   name        VARCHAR(100) NOT NULL,
                   notes       TEXT,
                   added_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
                   created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                   CHECK (src_ip IS NOT NULL OR src_mac IS NOT NULL)
               )"""
        )
    exists = execute(
        "SELECT 1 AS x FROM information_schema.tables WHERE table_name = 'known_applications'",
        fetch="one",
    )
    if not exists:
        execute(
            """CREATE TABLE known_applications (
                   id          SERIAL PRIMARY KEY,
                   domain      VARCHAR(255) NOT NULL UNIQUE,
                   name        VARCHAR(100) NOT NULL,
                   notes       TEXT,
                   added_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
                   created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
               )"""
        )


def ensure_detections_immutability():
    """Add the same tamper-proof triggers audit_logs already has to
    detections: block DELETE entirely, and block UPDATE of every column
    except is_resolved (the Resolve button's only legitimate write). Fresh
    `db/immutability.sql` runs get this directly; this is a fallback for
    databases provisioned before it was added. Needs table-owner/superuser
    privilege to create triggers -- under the restricted shadow_it_app role
    this is a safe no-op, caught and logged by the caller like the other
    ensure_* fallbacks."""
    exists = execute(
        "SELECT 1 AS x FROM pg_trigger WHERE tgname = 'trg_detections_no_delete'",
        fetch="one",
    )
    if exists:
        return
    execute(
        """CREATE OR REPLACE FUNCTION fn_detections_no_delete()
           RETURNS TRIGGER AS $$
           BEGIN
             RAISE EXCEPTION
               'Detection records are immutable — deleting scan logs is not permitted.';
           END;
           $$ LANGUAGE plpgsql"""
    )
    execute("DROP TRIGGER IF EXISTS trg_detections_no_delete ON detections")
    execute(
        """CREATE TRIGGER trg_detections_no_delete
           BEFORE DELETE ON detections
           FOR EACH ROW EXECUTE FUNCTION fn_detections_no_delete()"""
    )
    execute(
        """CREATE OR REPLACE FUNCTION fn_detections_guard_update()
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
           $$ LANGUAGE plpgsql"""
    )
    execute("DROP TRIGGER IF EXISTS trg_detections_guard_update ON detections")
    execute(
        """CREATE TRIGGER trg_detections_guard_update
           BEFORE UPDATE ON detections
           FOR EACH ROW EXECUTE FUNCTION fn_detections_guard_update()"""
    )
    execute(
        """DO $$
           BEGIN
             IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'shadow_it_app') THEN
               REVOKE DELETE ON detections FROM shadow_it_app;
             END IF;
           END $$"""
    )


def execute(query: str, params=None, fetch: str = None):
    """
    fetch = None  → execute only (INSERT/UPDATE/DELETE)
    fetch = 'one' → fetchone()
    fetch = 'all' → fetchall()
    """
    conn = get_connection()
    try:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(query, params)
            if fetch == "one":
                result = cur.fetchone()
            elif fetch == "all":
                result = cur.fetchall()
            else:
                result = None
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
