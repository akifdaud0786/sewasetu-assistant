# -*- coding: utf-8 -*-
"""
Idempotent schema changes, applied at container start (schema.sql only runs when the
database volume is first created, so a live database needs these applied in place).
"""

import sys
import time

import psycopg2

MIGRATIONS = [
    # wrong-OTP counter: a 6-digit code must not be guessable by retrying
    "ALTER TABLE otps ADD COLUMN IF NOT EXISTS attempts INTEGER DEFAULT 0",
    # application numbers are random; make a collision impossible rather than unlikely
    "CREATE UNIQUE INDEX IF NOT EXISTS uniq_application_no ON applications(application_no)",
    # one active application per mobile, enforced by the database for every channel
    "CREATE UNIQUE INDEX IF NOT EXISTS uniq_active_per_mobile ON applications(mobile) "
    "WHERE status IN ('PENDING', 'APPROVED', 'DEEMED_APPROVED')",
    "CREATE INDEX IF NOT EXISTS idx_app_block_status ON applications(block, status)",
    # a sign-in keeps one session id across refresh-token rotation, so ending the sign-in
    # (sign-out, Connected applications) stops its access tokens at once
    "ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS session_id VARCHAR(32)",
    "CREATE INDEX IF NOT EXISTS idx_rt_session ON oauth_refresh_tokens(session_id)",
    # an application being prepared through an assistant, one per signed-in mobile
    """CREATE TABLE IF NOT EXISTS agent_drafts (
        mobile        VARCHAR(15) PRIMARY KEY,
        data          JSONB NOT NULL DEFAULT '{}'::jsonb,
        doc_path      VARCHAR(200),
        doc_name      VARCHAR(200),
        updated_at    TIMESTAMP
    )""",
    # a one-time page where the applicant uploads the age proof from their own phone
    """CREATE TABLE IF NOT EXISTS agent_upload_links (
        token_hash  VARCHAR(64) PRIMARY KEY,
        mobile      VARCHAR(15),
        created_at  TIMESTAMP,
        expires_at  TIMESTAMP,
        used_at     TIMESTAMP
    )""",
    # what assistants did, without the personal data they sent (for audit and evals)
    """CREATE TABLE IF NOT EXISTS agent_calls (
        id         SERIAL PRIMARY KEY,
        at         TIMESTAMP,
        role       VARCHAR(10),
        subject    VARCHAR(80),
        client_id  VARCHAR(300),
        action     VARCHAR(50),
        ok         BOOLEAN,
        detail     VARCHAR(300)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_agent_calls_subject ON agent_calls(subject, at)",
]


def run(conn):
    cur = conn.cursor()
    cur.execute("SELECT pg_advisory_lock(727001)")
    try:
        for sql in MIGRATIONS:
            cur.execute(sql)
        conn.commit()
    finally:
        cur.execute("SELECT pg_advisory_unlock(727001)")
        conn.commit()
        cur.close()


def main():
    import app as portal  # reuse the portal's connection settings
    for attempt in range(60):
        try:
            conn = portal.get_db()
            break
        except psycopg2.OperationalError:
            time.sleep(2)
    else:
        print("migrate: database not reachable", file=sys.stderr)
        return 1
    run(conn)
    conn.close()
    print("migrate: schema up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
