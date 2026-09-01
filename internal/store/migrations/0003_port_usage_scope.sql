-- Tracks, per port_usage bucket, how many new sessions fell into each
-- internal/external scope category (see FlowSearchFilter.Scope). A single
-- (protocol, dst_port, application) bucket can genuinely span more than
-- one category — e.g. TCP/25 might see both an internal mail relay and an
-- external one — so this is four incrementally-maintained counters
-- (matching how sample_count/total_bytes already work: incremented only
-- on a brand-new session, not on every poll of an existing one) rather
-- than a single value, letting the UI show "internal", "outbound",
-- "inbound", "external", or "mixed" honestly instead of picking one
-- arbitrarily.
ALTER TABLE port_usage ADD COLUMN internal_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE port_usage ADD COLUMN outbound_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE port_usage ADD COLUMN inbound_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE port_usage ADD COLUMN external_count INTEGER NOT NULL DEFAULT 0;
