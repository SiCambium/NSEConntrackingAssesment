package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// IPWhoIs queries ipwho.is (free, no API key) — ported from
// SiCambium/NSELocalSSH's internal/nse/iplookup.go.
type IPWhoIs struct{ HTTP *http.Client }

func NewIPWhoIs() *IPWhoIs { return &IPWhoIs{HTTP: &http.Client{}} }

func (s *IPWhoIs) Key() string  { return "ipwhois" }
func (s *IPWhoIs) Name() string { return "ipwho.is" }

func (s *IPWhoIs) Lookup(ctx context.Context, ip string) (Result, error) {
	if _, err := rejectPrivate(ip); err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipwho.is/"+ip, nil)
	if err != nil {
		return Result{}, err
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var raw struct {
		Success    bool   `json:"success"`
		Message    string `json:"message"`
		Country    string `json:"country"`
		City       string `json:"city"`
		Connection struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return Result{}, fmt.Errorf("decoding response: %w", err)
	}
	if !raw.Success {
		return Result{}, fmt.Errorf("%s", strings.TrimSpace(raw.Message))
	}

	fields := map[string]string{"org": raw.Connection.Org, "isp": raw.Connection.ISP, "country": raw.Country, "city": raw.City}
	if raw.Connection.ASN != 0 {
		fields["asn"] = fmt.Sprintf("AS%d", raw.Connection.ASN)
	}
	summary := raw.Connection.Org
	if summary == "" {
		summary = raw.Connection.ISP
	}
	if raw.Country != "" {
		summary += " · " + raw.Country
	}
	if fields["asn"] != "" {
		summary += " · " + fields["asn"]
	}
	return Result{Source: s.Key(), Summary: strings.TrimSpace(strings.Trim(summary, " ·")), Fields: fields}, nil
}
