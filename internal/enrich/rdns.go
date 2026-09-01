package enrich

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// ReverseDNS resolves an IP's PTR record via the OS resolver — no
// external API at all, so it has no rate limit and no third party ever
// sees the query beyond whatever DNS resolver the host is already using.
type ReverseDNS struct {
	Resolver *net.Resolver
}

func NewReverseDNS() *ReverseDNS { return &ReverseDNS{Resolver: net.DefaultResolver} }

func (s *ReverseDNS) Key() string  { return "rdns" }
func (s *ReverseDNS) Name() string { return "Reverse DNS" }

func (s *ReverseDNS) Lookup(ctx context.Context, ip string) (Result, error) {
	if _, err := rejectPrivate(ip); err != nil {
		return Result{}, err
	}
	names, err := s.Resolver.LookupAddr(ctx, ip)
	if err != nil {
		return Result{}, fmt.Errorf("no PTR record: %w", err)
	}
	if len(names) == 0 {
		return Result{}, fmt.Errorf("no PTR record")
	}
	host := strings.TrimSuffix(names[0], ".")
	return Result{Source: s.Key(), Summary: host, Fields: map[string]string{"hostname": host}}, nil
}
