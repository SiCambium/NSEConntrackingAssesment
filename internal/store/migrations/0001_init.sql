-- ConnTrack schema. See PLAN.md / README.md for the rationale behind the
-- flow_sessions/flow_samples split (bounding raw-table growth by session
-- churn instead of poll count) and why port_usage is an incremental,
-- permanent rollup rather than something recomputed from prunable history.

CREATE TABLE IF NOT EXISTS firewalls (
  id              TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  host            TEXT NOT NULL,
  port            INTEGER NOT NULL DEFAULT 22,
  created_at      INTEGER NOT NULL,
  last_polled_at  INTEGER,
  last_poll_ok    INTEGER NOT NULL DEFAULT 0,
  last_poll_error TEXT,
  conntrack_limit INTEGER,
  conntrack_usage INTEGER,
  nat_usage       INTEGER,
  summary_updated_at INTEGER
);

CREATE TABLE IF NOT EXISTS flow_sessions (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  firewall_id   TEXT NOT NULL REFERENCES firewalls(id),
  session_key   TEXT NOT NULL,
  protocol      TEXT NOT NULL,
  origin_src    TEXT NOT NULL,
  origin_dst    TEXT NOT NULL,
  src_port      INTEGER,
  dst_port      INTEGER,
  nated_ip      TEXT,
  nated_port    INTEGER,
  tcp_state     TEXT,
  direction     TEXT,
  application   TEXT NOT NULL DEFAULT '',
  host_name     TEXT,
  ttl_last      INTEGER,
  tx_packets    INTEGER NOT NULL DEFAULT 0,
  tx_bytes      INTEGER NOT NULL DEFAULT 0,
  rx_packets    INTEGER NOT NULL DEFAULT 0,
  rx_bytes      INTEGER NOT NULL DEFAULT 0,
  is_dst_private INTEGER NOT NULL DEFAULT 0,
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  sample_count  INTEGER NOT NULL DEFAULT 1,
  closed_at     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_flow_sessions_open      ON flow_sessions(firewall_id, closed_at);
CREATE INDEX IF NOT EXISTS idx_flow_sessions_key        ON flow_sessions(firewall_id, session_key, closed_at);
CREATE INDEX IF NOT EXISTS idx_flow_sessions_dst        ON flow_sessions(firewall_id, origin_dst);
CREATE INDEX IF NOT EXISTS idx_flow_sessions_port       ON flow_sessions(firewall_id, protocol, dst_port);
CREATE INDEX IF NOT EXISTS idx_flow_sessions_app        ON flow_sessions(firewall_id, application);
CREATE INDEX IF NOT EXISTS idx_flow_sessions_last_seen  ON flow_sessions(last_seen);

CREATE TABLE IF NOT EXISTS flow_samples (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id    INTEGER NOT NULL REFERENCES flow_sessions(id),
  firewall_id   TEXT NOT NULL REFERENCES firewalls(id),
  event_type    TEXT NOT NULL, -- 'start' | 'heartbeat' | 'state_change' | 'end'
  seen_at       INTEGER NOT NULL,
  protocol      TEXT NOT NULL,
  origin_src    TEXT NOT NULL,
  origin_dst    TEXT NOT NULL,
  src_port      INTEGER,
  dst_port      INTEGER,
  nated_ip      TEXT,
  nated_port    INTEGER,
  tcp_state     TEXT,
  direction     TEXT,
  application   TEXT NOT NULL DEFAULT '',
  host_name     TEXT,
  ttl           INTEGER,
  tx_packets    INTEGER NOT NULL DEFAULT 0,
  tx_bytes      INTEGER NOT NULL DEFAULT 0,
  rx_packets    INTEGER NOT NULL DEFAULT 0,
  rx_bytes      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_flow_samples_firewall_seen ON flow_samples(firewall_id, seen_at);
CREATE INDEX IF NOT EXISTS idx_flow_samples_dst           ON flow_samples(firewall_id, origin_dst);
CREATE INDEX IF NOT EXISTS idx_flow_samples_dst_port      ON flow_samples(firewall_id, dst_port);
CREATE INDEX IF NOT EXISTS idx_flow_samples_protocol       ON flow_samples(firewall_id, protocol);
CREATE INDEX IF NOT EXISTS idx_flow_samples_app            ON flow_samples(firewall_id, application);
CREATE INDEX IF NOT EXISTS idx_flow_samples_session        ON flow_samples(session_id);

CREATE TABLE IF NOT EXISTS port_usage (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  firewall_id      TEXT NOT NULL REFERENCES firewalls(id),
  protocol         TEXT NOT NULL,
  dst_port         INTEGER NOT NULL DEFAULT 0,
  application      TEXT NOT NULL DEFAULT '',
  first_seen       INTEGER NOT NULL,
  last_seen        INTEGER NOT NULL,
  sample_count     INTEGER NOT NULL DEFAULT 0,
  total_bytes      INTEGER NOT NULL DEFAULT 0,
  distinct_dst_ips INTEGER NOT NULL DEFAULT 0,
  updated_at       INTEGER NOT NULL,
  UNIQUE (firewall_id, protocol, dst_port, application)
);
CREATE INDEX IF NOT EXISTS idx_port_usage_firewall  ON port_usage(firewall_id);
CREATE INDEX IF NOT EXISTS idx_port_usage_last_seen ON port_usage(last_seen);

CREATE TABLE IF NOT EXISTS port_usage_dst_ips (
  firewall_id TEXT NOT NULL REFERENCES firewalls(id),
  protocol    TEXT NOT NULL,
  dst_port    INTEGER NOT NULL DEFAULT 0,
  application TEXT NOT NULL DEFAULT '',
  dst_ip      TEXT NOT NULL,
  first_seen  INTEGER NOT NULL,
  PRIMARY KEY (firewall_id, protocol, dst_port, application, dst_ip)
);

CREATE TABLE IF NOT EXISTS approved_ports (
  id                    INTEGER PRIMARY KEY AUTOINCREMENT,
  firewall_id           TEXT NOT NULL REFERENCES firewalls(id),
  protocol              TEXT NOT NULL,
  dst_port              INTEGER NOT NULL DEFAULT 0,
  application           TEXT NOT NULL DEFAULT '',
  label                 TEXT,
  approved_by           TEXT,
  approved_at           INTEGER NOT NULL,
  UNIQUE (firewall_id, protocol, dst_port, application)
);

CREATE TABLE IF NOT EXISTS ip_reputation_cache (
  provider       TEXT NOT NULL,
  ip             TEXT NOT NULL,
  classification TEXT,
  is_noise       INTEGER NOT NULL DEFAULT 0,
  is_riot        INTEGER NOT NULL DEFAULT 0,
  name           TEXT,
  link           TEXT,
  message        TEXT,
  raw_json       TEXT,
  checked_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  lookup_error   TEXT,
  PRIMARY KEY (provider, ip)
);
CREATE INDEX IF NOT EXISTS idx_ip_reputation_expires ON ip_reputation_cache(expires_at);

CREATE TABLE IF NOT EXISTS provider_rate_limit (
  provider     TEXT PRIMARY KEY,
  window_date  TEXT NOT NULL, -- 'YYYY-MM-DD' UTC
  used_count   INTEGER NOT NULL DEFAULT 0,
  daily_budget INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS reputation_queue (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  provider     TEXT NOT NULL,
  ip           TEXT NOT NULL,
  firewall_id  TEXT NOT NULL REFERENCES firewalls(id),
  enqueued_at  INTEGER NOT NULL,
  priority     INTEGER NOT NULL DEFAULT 0,
  UNIQUE (provider, ip)
);
CREATE INDEX IF NOT EXISTS idx_reputation_queue_priority ON reputation_queue(priority DESC, enqueued_at ASC);
