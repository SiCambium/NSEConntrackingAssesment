# ConnTrack

A standalone companion to [NSELocalSSH](https://github.com/SiCambium/NSELocalSSH): polls one or more Cambium NSE3000/4000 firewalls' `show conntrack` data over SSH, stores it in SQLite, scores connections and ports for risk (local heuristics + GreyNoise threat intel), and generates a reviewable firewall deny-rule preview from what you've approved.

Multiple firewalls are tracked side by side and are never merged — every table is scoped by firewall ID.

## Setup

Two ways to run it — same backend, same dashboard, matching NSELocalSSH's own app/browser split:

**Plain browser** (any OS):
```bash
go build -o conntrackd ./cmd/conntrackd
./conntrackd -print-data-dir   # shows where config.yaml/DB/known_hosts live (outside this source folder)
./conntrackd
```
Open the printed URL (default `http://127.0.0.1:8090`).

**Native desktop window** (macOS only — needs CGO to link against Cocoa/WebKit):
```bash
sh scripts/package-macos.sh
open "dist/ConnTrack.app"
```
A WKWebView window around the same backend, on a random local port. The header's "Open in Browser" button (desktop mode only) hands the running session off to your default browser without closing the app window.

**You don't need to hand-edit a config file to add a firewall** — start either binary with zero firewalls configured and use the **Settings** tab in the dashboard to add one (name, host/IP, username, password, poll interval). It starts polling immediately, no restart. `configs/config.example.yaml` is there if you'd rather template it by hand.

**Why runtime data lives outside this folder:** this source tree is inside a OneDrive-synced directory. The database holds internal LAN IPs/hostnames/connection history, and the config holds SSH passwords — neither should end up auto-uploaded to cloud storage just because of where the binary was built from. `-print-data-dir` / `$CONNTRACK_HOME` control where they actually go (defaults to the OS per-user app-support directory, e.g. `~/Library/Application Support/ConnTrack` on macOS).

## What it does

- **Polls** each firewall on a per-firewall interval you choose from the Settings tab (1s/2s/5s/10s/20s/30s/1min, matching NSELocalSSH's own refresh picker — default 30s) via the same SSH session pattern and `show conntrack` / `service show conntrack` commands NSELocalSSH uses, and stores results as live sessions + an event history (start/state-change/heartbeat/end) — not one row per poll, so long-lived flows don't bloat the database.
- **Searches** on protocol, src/dst IP, src/dst port, direction, application (the device's own DPI tag), hostname, TCP state, time range, and byte volume.
- **Scores risk** (0–100, low/medium/high/critical) for both individual connections and aggregated port/application buckets, combining local heuristics (legacy admin ports, cleartext protocols, unrecognized DPI on an uncommon port, high-volume first contact, low sample confidence) with cached GreyNoise Community reputation lookups for public destination IPs.
- **Tracks an approved-ports list** — promote a port/application bucket you want to keep open — and generates a **deny-only, manual-review rule preview** for everything else: named deny rules field-compatible with NSELocalSSH's own Firewall screen, meant to be transcribed there. Nothing is ever pushed to a device from here (see caveat below).
- **Add/edit/remove firewalls from the GUI** — the Settings tab writes straight to `config.yaml` and reloads live pollers immediately (add/edit starts or restarts polling that firewall; remove stops polling it but keeps its history — nothing is deleted).
- **Sortable Flows/Ports tables** — click any column header to sort (including Risk), click again to reverse.
- **"Group by src IP → dst IP:port"** checkbox on the Flows tab collapses rows that only differ by ephemeral source port into one row with a count, summed bytes, the worst risk score in the group, and the earliest/latest seen times — useful when one host makes many short-lived connections to the same destination.
- **Approved column on Flows** — every row shows whether its (protocol, dst port, application) bucket is already on the approved-ports list, not just the aggregated Ports & Risk view.
- **"What do we know about this IP" lookups** — five free, keyless sources (ipwho.is, RDAP, reverse DNS, Team Cymru ASN, Shodan InternetDB), each independently toggleable in Settings and **off by default**. Enabled sources are queried together with one click on a destination IP in the Flows tab, shown as one combined result. Settings also shows each source's live health (OK / failing / not checked yet, last error, last-checked time) — see `internal/enrich`.
- **About tab** in the dashboard explains what's actually going on — data sources, privacy notes, the rule-preview caveat, and (if you're evaluating this) that the "Demo Firewall" data is only ever produced by the separate `cmd/replay` dev tool, never by the real app.

## GreyNoise budget

The free GreyNoise Community API needs no signup but caps unauthenticated use at **10 lookups/day**. conntrackd never looks up a private/RFC1918/CGNAT IP, caches every verdict (14 days, or 3 days for "unknown"), and drips the day's budget out on a timer instead of bursting through it — see `GET /api/firewalls/{id}/reputation/status` for current usage. If you outgrow 10/day, AbuseIPDB (free key, ~1,000/day) is a natural next `threatintel.Provider` to add — see `internal/threatintel/provider.go`.

## The five lookup sources (`internal/enrich`)

| Source | What it gives you | Cost |
|---|---|---|
| **ipwho.is** | Org/ISP/country/ASN | Free, no key |
| **RDAP** | Registered org/network, straight from the responsible registry (via ARIN's bootstrap redirect) | Free, no key, no real rate limit |
| **Reverse DNS (PTR)** | Hostname (e.g. `edge-star-shv-01-lhr6.facebook.com`) | Free, stdlib-only, no external API at all |
| **Team Cymru ASN** | ASN + org name via two DNS TXT queries | Free, no key, very lightweight |
| **Shodan InternetDB** | Open ports/hostnames/known CVEs Shodan has seen on that IP | Free, no key |

Each is independently on/off in Settings (all off by default), and the registry tracks live health per source — see `GET /api/settings/sources`. Not wired in: **ip-api.com** (redundant with ipwho.is) and bulk block lists (**Spamhaus DROP / FireHOL / abuse.ch**) — the latter are architecturally different (a periodic bulk download matched locally against all traffic, not a per-click lookup) and would be a good `internal/threatintel.Provider` addition if GreyNoise's 10/day ever feels limiting, since they have no per-lookup cap at all.

## Rule preview caveat

NSELocalSSH's own firewall code marks the device's outbound-filter `allow` action as **unconfirmed** over CLI — only `deny` has proven working syntax. So this tool never generates an allow rule or a catch-all deny-all; it only proposes named deny rules for specific ports/applications you haven't approved, relying on the device's own default policy for everything else. Review every row before applying it.

## Development

```bash
go test ./...
```

Parser tests run against real captured device output in `internal/nse/testdata/` (pulled from NSELocalSSH). Store/poller/risk/threatintel/ruleset tests run against a temp SQLite DB and a fake threat-intel provider — no live device or network access required.
