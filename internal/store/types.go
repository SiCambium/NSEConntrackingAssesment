package store

import "time"

type Firewall struct {
	ID               string
	Name             string
	Host             string
	Port             int
	CreatedAt        time.Time
	LastPolledAt     *time.Time
	LastPollOK       bool
	LastPollError    string
	ConntrackLimit   int
	ConntrackUsage   int
	NATUsage         int
	SummaryUpdatedAt *time.Time
}

// FlowSession is one live-or-recently-closed 5-tuple flow, upserted in
// place by the poller each time it reappears in a `show conntrack` sample.
type FlowSession struct {
	ID          int64
	FirewallID  string
	SessionKey  string
	Protocol    string
	OriginSrc   string
	OriginDst   string
	SrcPort     int
	DstPort     int
	NatedIP     string
	NatedPort   int
	TCPState    string
	Direction   string
	Application string
	HostName    string
	TTLLast     int

	TxPackets int64
	TxBytes   int64
	RxPackets int64
	RxBytes   int64

	IsSrcPrivate bool
	IsDstPrivate bool
	FirstSeen    time.Time
	LastSeen     time.Time
	SampleCount  int
	ClosedAt     *time.Time
}

// FlowSample is one append-only history event for a session: 'start',
// 'heartbeat', 'state_change', or 'end'.
type FlowSample struct {
	ID          int64
	SessionID   int64
	FirewallID  string
	EventType   string
	SeenAt      time.Time
	Protocol    string
	OriginSrc   string
	OriginDst   string
	SrcPort     int
	DstPort     int
	NatedIP     string
	NatedPort   int
	TCPState    string
	Direction   string
	Application string
	HostName    string
	TTL         int
	TxPackets   int64
	TxBytes     int64
	RxPackets   int64
	RxBytes     int64
}

// PortUsage is the permanent, incrementally-maintained rollup per
// (firewall, protocol, dst_port, application) bucket that risk scoring and
// the "ports in use" / approved-list UI operate on.
type PortUsage struct {
	ID             int64
	FirewallID     string
	Protocol       string
	DstPort        int
	Application    string
	FirstSeen      time.Time
	LastSeen       time.Time
	SampleCount    int
	TotalBytes     int64
	DistinctDstIPs int
	UpdatedAt      time.Time

	// Per-scope session counts — see migrations/0003_port_usage_scope.sql.
	InternalCount int
	OutboundCount int
	InboundCount  int
	ExternalCount int
}

// Scope summarizes a bucket's traffic direction: "internal" (LAN<->LAN
// only), "outbound" (LAN->WAN only), "inbound" (WAN->LAN only),
// "external" (WAN<->WAN only), "mixed" (more than one category seen), or
// "" if the bucket predates scope tracking and has never been updated
// since (all counts still zero).
func (u PortUsage) Scope() string {
	seen := 0
	last := ""
	if u.InternalCount > 0 {
		seen++
		last = "internal"
	}
	if u.OutboundCount > 0 {
		seen++
		last = "outbound"
	}
	if u.InboundCount > 0 {
		seen++
		last = "inbound"
	}
	if u.ExternalCount > 0 {
		seen++
		last = "external"
	}
	if seen == 0 {
		return ""
	}
	if seen > 1 {
		return "mixed"
	}
	return last
}

// ApprovedPort is a user decision: "leave this open." Promoted from a
// PortUsage bucket via the web UI.
type ApprovedPort struct {
	ID          int64
	FirewallID  string
	Protocol    string
	DstPort     int
	Application string
	Label       string
	ApprovedBy  string
	ApprovedAt  time.Time
}

// ReputationEntry is a cached threat-intel verdict for one IP from one
// provider.
type ReputationEntry struct {
	Provider       string
	IP             string
	Classification string
	IsNoise        bool
	IsRIOT         bool
	Name           string
	Link           string
	Message        string
	RawJSON        string
	CheckedAt      time.Time
	ExpiresAt      time.Time
	LookupError    string
}

// ReputationQueueItem is a pending IP awaiting a rate-limited lookup.
type ReputationQueueItem struct {
	ID         int64
	Provider   string
	IP         string
	FirewallID string
	EnqueuedAt time.Time
	Priority   int
}
