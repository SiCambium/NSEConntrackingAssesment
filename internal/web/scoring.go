package web

import (
	"strconv"
	"time"

	"conntrackd/internal/poller"
	"conntrackd/internal/risk"
	"conntrackd/internal/store"
)

// bucketKey matches store.ApprovedSet's "protocol|dst_port|application" key
// shape so the two can be looked up against each other directly.
func bucketKey(protocol string, dstPort int, application string) string {
	return protocol + "|" + strconv.Itoa(dstPort) + "|" + application
}

// scoreBucket computes a risk.RiskResult for one port_usage row, gathering
// cached reputation for every distinct destination IP the bucket has ever
// talked to (never triggering a new lookup — that only happens via the
// poller's Enqueue).
func (s *Server) scoreBucket(u store.PortUsage) risk.RiskResult {
	var reps []risk.ReputationInfo
	if s.reputation != nil {
		ips, err := s.store.DistinctDstIPsForBucket(u.FirewallID, u.Protocol, u.DstPort, u.Application)
		if err == nil {
			for _, ip := range ips {
				if poller.IsPrivateOrReserved(ip) {
					continue
				}
				if info, ok := s.reputation.CachedReputation(ip); ok {
					reps = append(reps, info)
				}
			}
		}
	}
	return risk.ScorePortUsage(risk.PortUsageInput{
		Protocol: u.Protocol, DstPort: u.DstPort, Application: u.Application,
		SampleCount: u.SampleCount, TotalBytes: u.TotalBytes, DistinctDstIPs: u.DistinctDstIPs,
		FirstSeen: u.FirstSeen, Now: time.Now().UTC(), Reputations: reps,
	})
}

// scoreSession computes a risk.RiskResult for one live/closed connection,
// using its port_usage bucket (if known) for sample-count confidence.
func (s *Server) scoreSession(fs store.FlowSession, bucketByKey map[string]store.PortUsage) risk.RiskResult {
	var repInfo *risk.ReputationInfo
	if !fs.IsDstPrivate && s.reputation != nil {
		if info, ok := s.reputation.CachedReputation(fs.OriginDst); ok {
			repInfo = &info
		}
	}
	bucketSampleCount := 0
	firstContact := false
	if b, ok := bucketByKey[bucketKey(fs.Protocol, fs.DstPort, fs.Application)]; ok {
		bucketSampleCount = b.SampleCount
		firstContact = b.DistinctDstIPs <= 1
	}
	return risk.ScoreConnection(risk.ConnectionInput{
		Protocol: fs.Protocol, DstPort: fs.DstPort, Application: fs.Application, Direction: fs.Direction,
		IsDstPrivate: fs.IsDstPrivate, Bytes: fs.TxBytes + fs.RxBytes, FirstSeen: fs.FirstSeen,
		Reputation: repInfo, BucketSampleCount: bucketSampleCount, BucketIsFirstContactForDst: firstContact,
		Now: time.Now().UTC(),
	})
}
