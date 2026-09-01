// Command replay seeds a throwaway database from real captured device
// output (the same fixtures internal/nse's parser tests use) plus a
// handful of synthetic flows chosen to exercise every risk heuristic, then
// serves the real dashboard against it. It never touches SSH or makes a
// live GreyNoise call — one destination IP's reputation is seeded directly
// into the cache to demonstrate the GREYNOISE_MALICIOUS path.
//
// This is how the search/risk/rule-preview flow gets verified end-to-end
// without access to a real NSE3000 — see PLAN.md's verification section.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"conntrackd/internal/config"
	"conntrackd/internal/nse"
	"conntrackd/internal/poller"
	"conntrackd/internal/sshclient"
	"conntrackd/internal/store"
	"conntrackd/internal/threatintel"
	"conntrackd/internal/threatintel/greynoise"
	"conntrackd/internal/web"
)

const firewallID = "demo"

// realCapture is SiCambium/NSELocalSSH's testdata/show_conntrack.txt,
// copied into internal/nse/testdata/ for the parser tests — reproduced
// here so replay is self-contained.
const realCapture = `show conntrack

Connection Track Entries:

==========================================================================================================================================


==========================================================================================================================================

Protocol | TTL | Origin_Src | Origin_Dst | Origin_Src_Port | Origin_Dst_Port | TX_packets | TX_bytes | RX_packets | RX_bytes | Nated_IP | Nated_Port | TCP_State | Direction | Application | Host Name
TCP | 3590 | 172.23.1.36 | 34.238.200.39 | 56345 | 443 | 24 | 5835 | 24 | 9386 | 192.168.1.171 | 56345 | ESTABLISHED | LAN TO WAN | amazon_aws |
UDP | 29 | 172.31.255.2 | 172.237.61.197 | 51878 | 3478 | 1 | 68 | 1 | 60 |  | 0 | N/A | UNKNOWN | icmp |
TCP | 3599 | 172.23.1.36 | 34.192.78.162 | 56445 | 443 | 194 | 57039 | 188 | 21232 | 192.168.1.171 | 56445 | ESTABLISHED | LAN TO WAN | amazon_aws | laptop
UDP | 26 | 172.23.1.36 | 172.23.0.1 | 52738 | 53 | 1 | 73 | 1 | 89 |  | 0 | N/A | LAN TO LAN | dns |
TCP | 88 | 172.23.1.38 | 1.0.0.2 | 53620 | 443 | 36 | 6410 | 56 | 16362 | 192.168.1.171 | 53620 | TIME_WAIT | LAN TO WAN | doh |
NSE-Caravan(config)#
`

const realSummary = `service show conntrack
Total Conntrack Limit: 262144
Total Conntrack Usage: 240
conntrack v1.4.7 (conntrack-tools): 157 flow entries have been shown.
Total NAT Usage: 157
NSE-Caravan(config)#
`

func main() {
	addr := flag.String("addr", "127.0.0.1:8091", "address to serve the demo dashboard on")
	dataDir := flag.String("data-dir", filepath.Join(os.TempDir(), "conntrack-replay"), "throwaway data directory (recreated each run)")
	flag.Parse()

	if err := os.RemoveAll(*dataDir); err != nil {
		log.Fatalf("clearing previous demo data dir: %v", err)
	}
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatalf("creating demo data dir: %v", err)
	}

	st, err := store.Open(*dataDir)
	if err != nil {
		log.Fatalf("opening store: %v", err)
	}
	defer st.Close()

	if err := st.SyncFirewall(firewallID, "Demo Firewall", "192.168.1.1", 22); err != nil {
		log.Fatalf("registering demo firewall: %v", err)
	}
	summary := nse.ParseConntrackSummary(realSummary)
	if err := st.RecordPollSuccess(firewallID, summary.Limit, summary.Usage, summary.NAT); err != nil {
		log.Fatalf("recording poll summary: %v", err)
	}

	mgr := threatintel.NewManager(st, greynoise.New(), 10, 14*24*time.Hour, 3*24*time.Hour)
	p := poller.New(firewallID, "Demo Firewall", nil, st, 30*time.Second, mgr.Enqueue)

	realFlows := nse.ParseConntrackFlows(realCapture)
	synthetic := syntheticFlows()
	telnet, ftp, mystery := synthetic[0], synthetic[1], synthetic[2]

	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	p.ApplyPoll(append(append([]nse.ConntrackFlow{}, realFlows...), telnet, ftp, mystery), t0)

	// Second poll 30s later: grow the long-lived flows (demonstrates the
	// heartbeat/counter-delta path) and let the doh (TIME_WAIT) and mystery
	// flows disappear (demonstrates session closing) — so the dashboard
	// shows both open and closed history, not just first-seen data.
	t1 := t0.Add(30 * time.Second)
	secondBatch := append(append([]nse.ConntrackFlow{}, realFlows[:4]...), telnet, ftp)
	for i := range secondBatch {
		secondBatch[i].TxBytes += 2000
		secondBatch[i].RxBytes += 4000
	}
	p.ApplyPoll(secondBatch, t1)

	// Seed a "malicious" GreyNoise verdict for the telnet destination
	// directly into the cache — demonstrates GREYNOISE_MALICIOUS without a
	// live network call.
	now := time.Now().UTC()
	if err := st.PutReputation(store.ReputationEntry{
		Provider: "greynoise", IP: "203.0.113.66", Classification: "malicious", IsNoise: true,
		Name: "Example Scanner Range", Message: "seeded for demo — not a real GreyNoise result",
		CheckedAt: now, ExpiresAt: now.Add(14 * 24 * time.Hour),
	}); err != nil {
		log.Fatalf("seeding reputation: %v", err)
	}
	if err := st.PutReputation(store.ReputationEntry{
		Provider: "greynoise", IP: "34.238.200.39", Classification: "benign", IsRIOT: true,
		Name: "Amazon AWS", CheckedAt: now, ExpiresAt: now.Add(14 * 24 * time.Hour),
	}); err != nil {
		log.Fatalf("seeding reputation: %v", err)
	}

	// Approve the well-established AWS HTTPS bucket so the Approved tab and
	// the rule-preview exclusion both have something to show.
	if err := st.ApprovePort(firewallID, "TCP", 443, "amazon_aws", "AWS HTTPS (bulk traffic)", "replay-demo"); err != nil {
		log.Fatalf("approving port: %v", err)
	}

	// A real config.Store + poller.Manager, deliberately started with zero
	// configured firewalls — "Demo Firewall" above stays pure seeded
	// history (nothing re-polls it, so its "polling OK" status and counts
	// stay put). This is what makes the Settings tab's add/edit/remove
	// flow live-testable: add a firewall there and watch it actually
	// start polling (and fail to connect, since it's not a real device —
	// that failure itself is visible proof the reload took effect).
	cfgStore, err := config.OpenStore(filepath.Join(*dataDir, "config.yaml"))
	if err != nil {
		log.Fatalf("opening config store: %v", err)
	}
	hostKeyCallback := sshclient.TrustedHostKeyCallback(filepath.Join(*dataDir, "known_hosts.json"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pollers := poller.NewManager(ctx, st, hostKeyCallback, mgr.Enqueue)
	pollers.Reload(cfgStore.Get().Firewalls)

	log.Printf("replay: seeded demo data for firewall %q in %s", firewallID, *dataDir)
	log.Printf("replay: serving dashboard on http://%s", *addr)
	srv := web.New(st, mgr, cfgStore, pollers)
	if err := http.ListenAndServe(*addr, srv); err != nil {
		log.Fatalf("http server: %v", err)
	}
}

// syntheticFlows adds cases the real capture doesn't: a legacy cleartext
// admin port, an FTP transfer, and a low-sample unrecognized-application
// flow on an uncommon port — enough variety to exercise every risk
// heuristic in internal/risk/rules.go.
func syntheticFlows() []nse.ConntrackFlow {
	return []nse.ConntrackFlow{
		{
			Protocol: "TCP", TTL: "3600", OriginSrc: "172.23.1.40", OriginDst: "203.0.113.66",
			SrcPort: "44210", DstPort: "23", TxPackets: 40, TxBytes: 4200, RxPackets: 60, RxBytes: 9000,
			NatedIP: "192.168.1.171", NatedPort: "44210", TCPState: "ESTABLISHED",
			Direction: "LAN TO WAN", Application: "telnet", HostName: "legacy-switch",
		},
		{
			Protocol: "TCP", TTL: "1800", OriginSrc: "172.23.1.41", OriginDst: "198.51.100.20",
			SrcPort: "51000", DstPort: "21", TxPackets: 200, TxBytes: 120000, RxPackets: 400, RxBytes: 900000,
			NatedIP: "192.168.1.171", NatedPort: "51000", TCPState: "ESTABLISHED",
			Direction: "LAN TO WAN", Application: "ftp", HostName: "",
		},
		{
			Protocol: "TCP", TTL: "60", OriginSrc: "172.23.1.42", OriginDst: "198.51.100.77",
			SrcPort: "60111", DstPort: "41337", TxPackets: 3, TxBytes: 400, RxPackets: 2, RxBytes: 300,
			NatedIP: "192.168.1.171", NatedPort: "60111", TCPState: "ESTABLISHED",
			Direction: "LAN TO WAN", Application: "", HostName: "",
		},
	}
}
