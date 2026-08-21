-- Phase 8 fixes.
--
-- 1. Reports were rate-limited per ip_hash but not deduplicated per letter, so
--    one person could hide any letter alone by reporting it twice. The log had
--    no letter_id, so dedupe was impossible. Add it, with a unique index doing
--    the enforcement at the database level rather than in application code.
ALTER TABLE wall_report_log ADD COLUMN letter_id TEXT;
CREATE UNIQUE INDEX idx_wall_report_once ON wall_report_log (letter_id, ip_hash);

-- 2. The post rate limit counted live rows in `wall`, and DELETE is a hard
--    delete, so an author could post 5, delete them, and post 5 more forever.
--    Count from an append-only log instead. It holds a hash and a timestamp
--    and no letter content, so the "private letters are never stored"
--    invariant is unaffected.
CREATE TABLE wall_post_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_hash     TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);
CREATE INDEX idx_wall_post_log_ip ON wall_post_log (ip_hash, created_at);
