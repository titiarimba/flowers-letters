CREATE TABLE wall (
  id          TEXT PRIMARY KEY,           -- crypto-random, 10 chars
  opening     TEXT NOT NULL,
  body        TEXT NOT NULL,
  signature   TEXT NOT NULL,
  flower      TEXT NOT NULL,
  created_at  INTEGER NOT NULL,           -- epoch ms
  delete_key  TEXT NOT NULL,              -- returned to the author exactly once
  visible     INTEGER NOT NULL DEFAULT 1,
  reports     INTEGER NOT NULL DEFAULT 0,
  ip_hash     TEXT
);
CREATE INDEX idx_wall_feed ON wall (visible, created_at DESC);

-- Rate limiting needs to look up posts by ip_hash, which idx_wall_feed doesn't cover.
CREATE INDEX idx_wall_ip ON wall (ip_hash, created_at);

-- Reports don't get their own row on `wall`, so a separate log backs the
-- per-ip_hash report rate limit (mass-hiding many different letters).
CREATE TABLE wall_report_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_hash     TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);
CREATE INDEX idx_wall_report_log_ip ON wall_report_log (ip_hash, created_at);
