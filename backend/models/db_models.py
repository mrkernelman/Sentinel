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
