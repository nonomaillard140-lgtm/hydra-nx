PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pass_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
    totp_secret TEXT NOT NULL DEFAULT '',
    recovery_hashes_json TEXT NOT NULL DEFAULT '[]',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    banned INTEGER NOT NULL DEFAULT 0,
    telegram_id TEXT NOT NULL DEFAULT '',
    referred_by INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    ua TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    expires_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    price_cents INTEGER NOT NULL,
    duration_hours INTEGER NOT NULL,
    max_devices INTEGER NOT NULL,
    daily_credits INTEGER NOT NULL,
    features_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    plan_id INTEGER NOT NULL REFERENCES plans(id),
    user_id INTEGER REFERENCES users(id),
    max_devices INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    signature TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS licenses_user_idx ON licenses(user_id);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('L7','L4')),
    size INTEGER NOT NULL DEFAULT 0,
    authorized INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, name)
);

CREATE TABLE IF NOT EXISTS list_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    list_id INTEGER NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
    value TEXT NOT NULL,
    UNIQUE(list_id, value)
);
CREATE INDEX IF NOT EXISTS list_items_list_idx ON list_items(list_id);

CREATE TABLE IF NOT EXISTS paths (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    raw TEXT NOT NULL,
    encoded_variants_json TEXT NOT NULL DEFAULT '[]',
    tags TEXT NOT NULL DEFAULT '',
    UNIQUE(user_id, raw)
);

CREATE TABLE IF NOT EXISTS cracks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    list_id INTEGER NOT NULL REFERENCES lists(id),
    path_id INTEGER NOT NULL REFERENCES paths(id),
    status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed','cancelled')),
    started_at DATETIME,
    finished_at DATETIME,
    stats_json TEXT NOT NULL DEFAULT '{}',
    authorization_confirmed INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS cracks_user_idx ON cracks(user_id);

CREATE TABLE IF NOT EXISTS hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crack_id INTEGER NOT NULL REFERENCES cracks(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    path TEXT NOT NULL,
    vuln TEXT NOT NULL,
    service TEXT NOT NULL,
    secret_redacted TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    points INTEGER NOT NULL DEFAULT 0,
    cash_score INTEGER NOT NULL DEFAULT 0,
    smtp_usable INTEGER NOT NULL DEFAULT 0,
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(secret_hash, service)
);
CREATE INDEX IF NOT EXISTS hits_user_idx ON hits(user_id);
CREATE INDEX IF NOT EXISTS hits_crack_idx ON hits(crack_id);

CREATE TABLE IF NOT EXISTS hit_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hit_id INTEGER NOT NULL REFERENCES hits(id) ON DELETE CASCADE,
    addon TEXT NOT NULL,
    result_json TEXT NOT NULL,
    checked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hit_id INTEGER REFERENCES hits(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    transport TEXT NOT NULL CHECK(transport IN ('smtp','api')),
    from_addr TEXT NOT NULL,
    to_addr TEXT NOT NULL,
    subject TEXT NOT NULL,
    status TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    sent_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS sends_user_date_idx ON sends(user_id, sent_at);

CREATE TABLE IF NOT EXISTS mailers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hit_id INTEGER REFERENCES hits(id),
    host TEXT NOT NULL,
    url TEXT NOT NULL,
    filename TEXT NOT NULL,
    password TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL,
    smtp_configured INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    deployed_at DATETIME,
    removed_at DATETIME
);

CREATE TABLE IF NOT EXISTS public_lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('L7','L4','PATHS')),
    filename TEXT NOT NULL UNIQUE,
    size_bytes INTEGER NOT NULL,
    lines INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    format TEXT NOT NULL CHECK(format IN ('txt','csv')),
    published_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    published_by INTEGER REFERENCES users(id),
    downloads INTEGER NOT NULL DEFAULT 0,
    hidden INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS credits_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    delta INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS credits_user_date_idx ON credits_ledger(user_id, created_at);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    addon TEXT NOT NULL DEFAULT '*',
    channel TEXT NOT NULL CHECK(channel IN ('telegram','discord','webhook','smtp')),
    target TEXT NOT NULL,
    secret_json TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 1,
    UNIQUE(user_id, addon, channel, target)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER REFERENCES users(id),
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    meta_json TEXT NOT NULL DEFAULT '{}',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS audit_date_idx ON audit_log(created_at);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO plans(name, price_cents, duration_hours, max_devices, daily_credits, features_json) VALUES
('Jour', 10000, 24, 1, 500, '{"scan":true,"exports":true}'),
('Semaine', 50000, 168, 2, 1500, '{"scan":true,"exports":true,"notifications":true}'),
('Mois', 150000, 720, 4, 5000, '{"scan":true,"exports":true,"notifications":true,"api":true}');

INSERT OR IGNORE INTO settings(key, value) VALUES
('concurrency', '4'), ('timeout_seconds', '12'), ('host_limit', '2'),
('maintenance', 'false'), ('public_hits', 'false'), ('grace_hours', '0');
