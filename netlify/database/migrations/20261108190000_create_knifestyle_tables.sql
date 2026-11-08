CREATE TABLE accounts (
  username_key TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  is_admin BOOLEAN NOT NULL DEFAULT FALSE,
  is_owner BOOLEAN NOT NULL DEFAULT FALSE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  expires_utc TIMESTAMPTZ,
  created_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  device_id TEXT,
  last_device_id TEXT,
  last_seen_utc TIMESTAMPTZ
);
CREATE UNIQUE INDEX accounts_single_owner ON accounts (is_owner) WHERE is_owner = TRUE;
CREATE TABLE license_keys (
  id TEXT PRIMARY KEY,
  key_hash TEXT NOT NULL UNIQUE,
  duration_code TEXT NOT NULL CHECK (duration_code IN ('month_1', 'months_3', 'year_1', 'lifetime')),
  created_utc TIMESTAMPTZ NOT NULL,
  redeemed_utc TIMESTAMPTZ,
  redeemed_by TEXT
);
CREATE TABLE login_sessions (
  token_hash TEXT PRIMARY KEY,
  username_key TEXT NOT NULL REFERENCES accounts(username_key) ON DELETE CASCADE,
  expires_utc TIMESTAMPTZ NOT NULL
);
CREATE INDEX login_sessions_expiry ON login_sessions (expires_utc);
CREATE TABLE auth_attempts (
  bucket TEXT PRIMARY KEY,
  started_utc TIMESTAMPTZ NOT NULL,
  attempt_count INTEGER NOT NULL
);
CREATE TABLE releases (
  id SMALLINT PRIMARY KEY CHECK (id = 1),
  version TEXT NOT NULL,
  file_name TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  updated_utc TIMESTAMPTZ NOT NULL,
  content BYTEA NOT NULL
);

