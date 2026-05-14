CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS manifests (
    name                TEXT    NOT NULL,
    version             TEXT    NOT NULL,
    source              TEXT    NOT NULL CHECK (source IN ('bundled','registry','local','git')),
    signature_verified  INTEGER NOT NULL,
    risk_score          INTEGER NOT NULL,
    installed_at        INTEGER NOT NULL,
    content             TEXT    NOT NULL,
    compiled_cache      BLOB,
    PRIMARY KEY (name, version)
);
CREATE INDEX IF NOT EXISTS idx_manifests_name ON manifests(name);

CREATE TABLE IF NOT EXISTS running_servers (
    id                TEXT PRIMARY KEY,
    manifest_name     TEXT NOT NULL,
    manifest_version  TEXT NOT NULL,
    host              TEXT,
    pid               INTEGER,
    sandbox_backend   TEXT NOT NULL,
    sandbox_id        TEXT NOT NULL,
    started_at        INTEGER NOT NULL,
    status            TEXT NOT NULL CHECK (status IN ('starting','running','exiting','crashed','exited')),
    FOREIGN KEY (manifest_name, manifest_version) REFERENCES manifests(name, version)
);

CREATE TABLE IF NOT EXISTS approvals (
    id                 TEXT PRIMARY KEY,
    server_id          TEXT NOT NULL,
    tool               TEXT NOT NULL,
    args_hash          TEXT NOT NULL,
    args_summary       TEXT NOT NULL,
    decision           TEXT CHECK (decision IN ('allow','deny','pending','timeout')),
    requested_at       INTEGER NOT NULL,
    decided_at         INTEGER,
    remembered_until   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_approvals_pending
    ON approvals(decision) WHERE decision = 'pending';
CREATE INDEX IF NOT EXISTS idx_approvals_remember
    ON approvals(server_id, tool, args_hash, remembered_until);

CREATE TABLE IF NOT EXISTS registry_cache (
    name         TEXT NOT NULL,
    version      TEXT NOT NULL,
    fetched_at   INTEGER NOT NULL,
    bundle_sha256 TEXT NOT NULL,
    PRIMARY KEY (name, version)
);

CREATE TABLE IF NOT EXISTS sandbox_uids (
    uid           INTEGER PRIMARY KEY,
    username      TEXT NOT NULL,
    server_id     TEXT,
    allocated_at  INTEGER
);

CREATE TABLE IF NOT EXISTS daemon_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
