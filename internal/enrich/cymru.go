package enrich

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// TeamCymru resolves an IPv4 address to its announcing ASN via Team
// Cymru's DNS-based whois (two plain TXT queries, no HTTP API, no key —
// see https://team-cymru.com/community-services/ip-asn-mapping/). IPv6 is
// not supported here (it uses a different nibble-reversed zone) — Lookup
// returns a clear error for it rather than guessing.
type TeamCymru struct {
	Resolver *net.Resolver
}

func NewTeamCymru() *TeamCymru { return &TeamCymru{Resolver: net.DefaultResolver} }

func (s *TeamCymru) Key() string  { return "cymru" }
func (s *TeamCymru) Name() string { return "Team Cymru ASN" }

func (s *TeamCymru) Lookup(ctx context.Context, ip string) (Result, error) {
	parsed, err := rejectPrivate(ip)
	if err != nil {
		return Result{}, err
	}
	v4 := parsed.To4()
	if v4 == nil {
		return Result{}, fmt.Errorf("IPv6 not supported by this lookup")
	}
	reversed := fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])

	originTXT, err := s.Resolver.LookupTXT(ctx, reversed+".origin.asn.cymru.com")
	if err != nil || len(originTXT) == 0 {
		return Result{}, fmt.Errorf("no ASN mapping found")
	}
	// "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
	originFields := splitPipe(originTXT[0])
	if len(originFields) < 3 {
		return Result{}, fmt.Errorf("unexpected origin response format")
	}
	asn, prefix, country := originFields[0], originFields[1], originFields[2]

	asName := ""
	if nameTXT, err := s.Resolver.LookupTXT(ctx, "AS"+asn+".asn.cymru.com"); err == nil && len(nameTXT) > 0 {
		// "15169 | US | arin | 1992-12-01 | GOOGLE, US"
		nameFields := splitPipe(nameTXT[0])
		if len(nameFields) >= 5 {
			asName = nameFields[4]
		}
	}

	fields := map[string]string{"asn": "AS" + asn, "prefix": prefix, "country": country, "as_name": asName}
	summary := "AS" + asn
	if asName != "" {
		summary += " (" + asName + ")"
	}
	summary += " · " + prefix + " · " + country
	return Result{Source: s.Key(), Summary: summary, Fields: fields}, nil
}

func splitPipe(s string) []string {
	parts := strings.Split(s, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
