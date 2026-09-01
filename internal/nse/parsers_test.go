package nse

import (
	"os"
	"testing"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return string(b)
}

func TestParseConntrackFlows(t *testing.T) {
	raw := readFixture(t, "show_conntrack.txt")
	rows := ParseConntrackFlows(raw)
	if len(rows) != 5 {
		t.Fatalf("got %d rows, want 5", len(rows))
	}

	want := ConntrackFlow{
		Protocol: "TCP", TTL: "3590", OriginSrc: "172.23.1.36", OriginDst: "34.238.200.39",
		SrcPort: "56345", DstPort: "443", TxPackets: 24, TxBytes: 5835, RxPackets: 24, RxBytes: 9386,
		NatedIP: "192.168.1.171", NatedPort: "56345", TCPState: "ESTABLISHED",
		Direction: "LAN TO WAN", Application: "amazon_aws", HostName: "",
	}
	if rows[0] != want {
		t.Fatalf("row 0 = %+v, want %+v", rows[0], want)
	}

	// UDP row with no NAT port and N/A tcp_state (normalized to "").
	udp := rows[1]
	if udp.Protocol != "UDP" || udp.TTL != "29" || udp.DstPort != "3478" {
		t.Fatalf("row 1 unexpected: %+v", udp)
	}
	if udp.NatedPort != "" {
		t.Fatalf("expected NatedPort '0' to normalize to empty, got %q", udp.NatedPort)
	}
	if udp.TCPState != "" {
		t.Fatalf("expected TCPState 'N/A' to normalize to empty, got %q", udp.TCPState)
	}
	if udp.Application != "icmp" {
		t.Fatalf("expected application icmp, got %q", udp.Application)
	}

	// Row with a trailing host name column.
	laptop := rows[2]
	if laptop.HostName != "laptop" {
		t.Fatalf("expected host_name 'laptop', got %q", laptop.HostName)
	}

	// LAN-to-LAN DNS row.
	dns := rows[3]
	if dns.Direction != "LAN TO LAN" || dns.Application != "dns" {
		t.Fatalf("row 3 unexpected: %+v", dns)
	}

	doh := rows[4]
	if doh.TCPState != "TIME_WAIT" || doh.Application != "doh" {
		t.Fatalf("row 4 unexpected: %+v", doh)
	}
}

func TestParseConntrackFlows_SkipsHeaderAndSeparators(t *testing.T) {
	raw := "show conntrack\n" +
		"Connection Track Entries:\n" +
		"==========\n" +
		"Protocol | TTL | Origin_Src | Origin_Dst | Origin_Src_Port | Origin_Dst_Port | TX_packets | TX_bytes | RX_packets | RX_bytes | Nated_IP | Nated_Port | TCP_State | Direction | Application | Host Name\n" +
		"==========\n" +
		"NSE-Caravan(config)#\n"
	rows := ParseConntrackFlows(raw)
	if len(rows) != 0 {
		t.Fatalf("expected 0 rows for a header-only capture, got %d", len(rows))
	}
}

func TestParseConntrackSummary(t *testing.T) {
	raw := readFixture(t, "probe_service_show_conntrack.txt")
	s := ParseConntrackSummary(raw)
	if s.Limit != 262144 {
		t.Errorf("Limit = %d, want 262144", s.Limit)
	}
	if s.Usage != 240 {
		t.Errorf("Usage = %d, want 240", s.Usage)
	}
	if s.NAT != 157 {
		t.Errorf("NAT = %d, want 157", s.NAT)
	}
	if s.Flows != 157 {
		t.Errorf("Flows = %d, want 157", s.Flows)
	}
}
