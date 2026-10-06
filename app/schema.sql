-- Sewa Setu Old Age Pension Portal - schema
-- NOTE: seed.sql (shipped separately) loads after this and contains the
-- production data. Do not re-run against a live database.

CREATE TABLE IF NOT EXISTS applications (
    id              SERIAL PRIMARY KEY,
    application_no  VARCHAR(20),
    applicant_name  VARCHAR(100),
    mobile          VARCHAR(15),
    dob             DATE,
    gender          VARCHAR(10),
    marital_status  VARCHAR(20),
    husband_name    VARCHAR(100),
    husband_employer VARCHAR(100),
    village         VARCHAR(100),
    block           VARCHAR(50),
    bank_account    VARCHAR(30),
    ifsc            VARCHAR(15),
    doc_path        VARCHAR(200),
    status          VARCHAR(20) DEFAULT 'PENDING',
    submitted_at    TIMESTAMP,
    decided_at      TIMESTAMP,
    decided_by      VARCHAR(50)
);

-- Status portal accounts (created at submission time)
CREATE TABLE IF NOT EXISTS portal_users (
    mobile        VARCHAR(15) PRIMARY KEY,
    password_hash VARCHAR(80)
);

CREATE TABLE IF NOT EXISTS otps (
    id         SERIAL PRIMARY KEY,
    mobile     VARCHAR(15),
    code       VARCHAR(6),
    created_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_app_mobile ON applications(mobile);
CREATE INDEX IF NOT EXISTS idx_app_status ON applications(status);

-- Who did what to an application, and when (submit / withdraw / approve / reject / deemed).
CREATE TABLE IF NOT EXISTS audit_log (
    id             SERIAL PRIMARY KEY,
    application_id INTEGER,
    action         VARCHAR(20),
    actor          VARCHAR(50),
    note           VARCHAR(500),
    at             TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_app ON audit_log(application_id);
CREATE INDEX IF NOT EXISTS idx_app_status_submitted ON applications(status, submitted_at);

-- OAuth 2.1 authorization server (third-party applications acting for a citizen or officer)
CREATE TABLE IF NOT EXISTS oauth_keys (
    kid         VARCHAR(32) PRIMARY KEY,
    private_pem TEXT,
    created_at  TIMESTAMP
);
CREATE TABLE IF NOT EXISTS oauth_clients (
    id            SERIAL PRIMARY KEY,
    client_id     VARCHAR(300) UNIQUE,
    client_name   VARCHAR(100),
    redirect_uris JSONB,
    secret_hash   VARCHAR(64),
    kind          VARCHAR(10),           -- dcr | cimd
    created_at    TIMESTAMP,
    fetched_at    TIMESTAMP
);
CREATE TABLE IF NOT EXISTS oauth_requests (          -- an authorization in progress (login -> consent)
    id             VARCHAR(64) PRIMARY KEY,
    params         JSONB,
    subject        VARCHAR(80),
    role           VARCHAR(10),
    pending_mobile VARCHAR(15),
    created_at     TIMESTAMP
);
CREATE TABLE IF NOT EXISTS oauth_codes (
    code_hash      VARCHAR(64) PRIMARY KEY,
    client_id      VARCHAR(300),
    redirect_uri   VARCHAR(500),
    scope          VARCHAR(20),
    code_challenge VARCHAR(128),
    resource       VARCHAR(300),
    subject        VARCHAR(80),
    role           VARCHAR(10),
    created_at     TIMESTAMP
);
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (   -- one row per sign-in; expires_at is the session's absolute end
    token_hash  VARCHAR(64) PRIMARY KEY,
    client_id   VARCHAR(300),
    client_name VARCHAR(100),
    subject    VARCHAR(80),
    role       VARCHAR(10),
    scope      VARCHAR(20),
    resource   VARCHAR(300),
    created_at TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS oauth_program_tokens (     -- admin-issued, long-lived, for unattended use
    id         SERIAL PRIMARY KEY,
    jti        VARCHAR(32) UNIQUE,
    label      VARCHAR(100),
    subject    VARCHAR(80),
    audience   VARCHAR(300),
    issued_by  VARCHAR(50),
    created_at TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP
);
