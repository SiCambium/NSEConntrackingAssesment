package poller

import (
	"net"
	"strconv"
	"strings"

	"conntrackd/internal/nse"
)

// SessionKey identifies one logical flow independent of poll timing:
// protocol + both endpoints + both ports. NAT/ephemeral src ports are part
// of the device's own identity for the flow, so they're included as-is
// rather than normalized away.
func SessionKey(f nse.ConntrackFlow) string {
	return strings.ToUpper(f.Protocol) + "|" + f.OriginSrc + "|" + f.OriginDst + "|" + f.SrcPort + "|" + f.DstPort
}

// IsPrivateOrReserved reports whether ip should never be sent to an
// external threat-intel provider: RFC1918, loopback, link-local, CGNAT
// (100.64.0.0/10 — not classified as private by the stdlib), and IPv6
// ULA/loopback/link-local. Unparseable input is treated as private (fail
// closed — never leak a lookup for a value we can't classify).
func IsPrivateOrReserved(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// CGNAT range 100.64.0.0/10.
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
		return false
	}
	return false
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
