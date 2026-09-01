-- Tracks whether the *source* address is private/RFC1918/CGNAT, mirroring
-- the existing is_dst_private column. Together the two let a query
-- classify a flow's scope without re-parsing IPs: internal<->internal,
-- internal->external (outbound), external->internal (inbound), or
-- external<->external. Defaults to 0 for any row that existed before
-- this migration; since it's only computed at session creation (not on
-- update), an already-open session keeps 0 until it closes and a fresh
-- one opens with the real value — harmless, just a transient
-- inaccuracy for whatever was mid-flight at upgrade time.
ALTER TABLE flow_sessions ADD COLUMN is_src_private INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_flow_sessions_scope ON flow_sessions(firewall_id, is_src_private, is_dst_private);
