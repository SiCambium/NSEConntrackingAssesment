# ConnTrack — design notes

This is the design record the code comments point back to. See [README.md](README.md) for setup/usage.

## Context

Companion to [NSELocalSSH](https://github.com/SiCambium/NSELocalSSH)'s "Connection tracking" dashboard element: capture `show conntrack` history into a real database, search it on every useful field, score connections/ports for risk (including external threat intel), and use that to decide which ports to actually keep open. Multiple firewalls are tracked without ever being merged together.

## Decisions

- **Standalone Go service**, decoupled from NSELocalSSH — connects to each firewall over SSH itself, reusing NSELocalSSH's proven SSH session pattern (`internal/sshclient`, ported from its `internal/nse/client.go`) and conntrack field model (`internal/nse/parsers.go`, ported from its `internal/nse/parsers.go`), verified against its real captured test fixtures.
- **Multiple firewalls, never merged** — every table is scoped by `firewall_id`. No cross-firewall aggregation anywhere.
- **Runtime data lives outside the source tree.** This source folder is inside OneDrive sync; the database holds internal LAN topology and the config holds SSH passwords. Both default to the OS app-support directory (`config.DataDir()`), overridable via `$CONNTRACK_HOME`.
- **Schema**: `flow_sessions` (upserted, one row per live/recently-closed 5-tuple) + `flow_samples` (append-only, event-triggered: start/state_change/heartbeat/end — *not* one row per poll, which would bloat the table with duplicate "still here" rows for every long-lived flow). `port_usage` is a **permanent, incrementally-upserted** rollup (never recomputed from prunable history, so its totals survive pruning) — this is what risk scoring and the approved-ports UI read. `port_usage_dst_ips` makes `distinct_dst_ips` exact forever. See `internal/store/migrations/0001_init.sql`.
- **Retention**: 90-day default for closed `flow_sessions`/`flow_samples` (open sessions never pruned); `port_usage`/`approved_ports`/`ip_reputation_cache` are permanent. See `internal/store/prune.go`.
- **Poll interval**: user-selectable per firewall from a fixed set (1/2/5/10/20/30/60s, matching NSELocalSSH's own dashboard refresh picker) rather than free text, so nobody accidentally hammers the device. Default 30s. A UDP flow that starts and expires entirely within one poll gap can be missed — inherent to polling a CLI snapshot.
- **Live reload, no restart**: `internal/poller.Manager` diffs the configured firewall set on every config change (add/edit/remove via the Settings UI) and starts/stops/restarts individual pollers accordingly — see `internal/config.Store` (validates + persists + commits atomically) and `internal/poller/manager.go`.
- **Risk scoring** (`internal/risk`) is an additive 0–100 heuristic, **computed on read, not persisted** (reputation/usage inputs change independently of flow data, so a stored score would just go stale), combining local signals (legacy admin ports, cleartext protocols, unrecognized DPI on an uncommon port, high-volume first contact, low sample confidence) with cached threat-intel verdicts.
- **GreyNoise Community** (`internal/threatintel`) is free and keyless but capped at 10 lookups/day unauthenticated. Never queries private/RFC1918/CGNAT IPs, caches every verdict (14d / 3d negative), and drips the day's budget out via a durable queue instead of bursting. `Provider` is an interface specifically so AbuseIPDB (free key, ~1000/day) or a bulk-list matcher (Spamhaus DROP / FireHOL / abuse.ch — no per-IP limit at all) can be added later without a rework.
- **Rule preview is deny-only and manual-review-only.** NSELocalSSH's own firewall code marks the device's `allow` filter action as *unconfirmed* over CLI — only `deny` is proven. So `internal/ruleset` never emits an allow rule or a catch-all deny-all; it only proposes named deny rules for unapproved ports/applications, field-compatible with NSELocalSSH's own filter-rule model so a row can be transcribed directly into that app's Firewall screen. Nothing is ever pushed to a device from here.
- **Two run modes, one backend** (`internal/appserver` wires everything once): `cmd/conntrackd` is plain-browser mode (fixed port, open the URL yourself); `cmd/conntrack-app` is a native desktop window (webview_go, matching NSELocalSSH's `cmd/nse-app`/`cmd/nse-status` split), listening on a random local port with an "Open in Browser" escape hatch bound into the page as `window.conntrackOpenInBrowser()`.

## Verification

- Parser tests run against real captured device output in `internal/nse/testdata/` (pulled from NSELocalSSH).
- Store/poller/risk/threatintel/ruleset/config tests run against a temp SQLite DB and a fake threat-intel provider — no live device or network access required.
- `cmd/replay` seeds realistic + edge-case data (plus a live, intentionally-unreachable firewall entry) and serves the real dashboard, so the whole search/risk/rule-preview/Settings flow — including live add/edit/remove-firewall reload — can be exercised end-to-end without a real NSE3000.
- Live SSH polling against a real device, and an actual GreyNoise API call, need a real firewall and network egress this environment doesn't have — that's on you to confirm once it's pointed at real hardware.
