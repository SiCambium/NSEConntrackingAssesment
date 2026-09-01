package enrich

import (
	"fmt"
	"net"
)

// rejectPrivate is called by every source before making a network call —
// private/loopback/link-local/CGNAT addresses never resolve usefully
// against a public lookup service and would just waste it.
func rejectPrivate(ip string) (net.IP, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("invalid IP address")
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() ||
		parsed.IsLinkLocalMulticast() || parsed.IsUnspecified() || parsed.IsMulticast() {
		return nil, fmt.Errorf("private address, nothing to look up")
	}
	if v4 := parsed.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return nil, fmt.Errorf("CGNAT address, nothing to look up")
	}
	return parsed, nil
}
