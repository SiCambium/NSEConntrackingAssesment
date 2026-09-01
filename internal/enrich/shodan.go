package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// ShodanInternetDB queries Shodan's free, keyless InternetDB endpoint —
// not a live scan, but what Shodan has previously observed exposed on
// this IP (open ports, hostnames, known CVEs). A different, complementary
// signal from reputation/WHOIS: "what does this address expose," not
// "who owns it" or "is it dangerous." See https://internetdb.shodan.io/.
type ShodanInternetDB struct{ HTTP *http.Client }

func NewShodanInternetDB() *ShodanInternetDB { return &ShodanInternetDB{HTTP: &http.Client{}} }

func (s *ShodanInternetDB) Key() string  { return "shodan" }
func (s *ShodanInternetDB) Name() string { return "Shodan InternetDB" }

func (s *ShodanInternetDB) Lookup(ctx context.Context, ip string) (Result, error) {
	if _, err := rejectPrivate(ip); err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://internetdb.shodan.io/"+ip, nil)
	if err != nil {
		return Result{}, err
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Result{Source: s.Key(), Summary: "not seen in Shodan's index", Fields: map[string]string{}}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var raw struct {
		Ports     []int    `json:"ports"`
		Hostnames []string `json:"hostnames"`
		Vulns     []string `json:"vulns"`
		Tags      []string `json:"tags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return Result{}, fmt.Errorf("decoding response: %w", err)
	}

	portStrs := make([]string, len(raw.Ports))
	for i, p := range raw.Ports {
		portStrs[i] = strconv.Itoa(p)
	}
	fields := map[string]string{
		"ports": strings.Join(portStrs, ","), "hostnames": strings.Join(raw.Hostnames, ","),
		"vulns": strings.Join(raw.Vulns, ","), "tags": strings.Join(raw.Tags, ","),
	}
	summary := fmt.Sprintf("%d open port(s)", len(raw.Ports))
	if len(portStrs) > 0 {
		summary += ": " + strings.Join(portStrs, ", ")
	}
	if len(raw.Vulns) > 0 {
		summary += fmt.Sprintf(" · %d known CVE(s)", len(raw.Vulns))
	}
	return Result{Source: s.Key(), Summary: summary, Fields: fields}, nil
}
