package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// RDAP queries ARIN's public bootstrap redirect server, which forwards
// the request to whichever RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC) actually
// manages that address block — no key, no per-registry endpoint
// hardcoding needed. See
// https://www.arin.net/blog/2020/12/11/buckle-up-change-of-address-coming-for-arins-bootstrap-server/
type RDAP struct{ HTTP *http.Client }

func NewRDAP() *RDAP { return &RDAP{HTTP: &http.Client{}} }

func (s *RDAP) Key() string  { return "rdap" }
func (s *RDAP) Name() string { return "RDAP" }

// rdapEntity is the RFC 9083 entity shape, trimmed to what we read. Org
// name resolution from vcardArray is best-effort — jCard structure varies
// enough between RIRs that this won't always find one; falling back to
// the network's own handle/name is still a useful answer.
type rdapEntity struct {
	Roles      []string `json:"roles"`
	VCardArray []any    `json:"vcardArray"`
}

func (e rdapEntity) orgName() string {
	if len(e.VCardArray) != 2 {
		return ""
	}
	props, ok := e.VCardArray[1].([]any)
	if !ok {
		return ""
	}
	for _, p := range props {
		prop, ok := p.([]any)
		if !ok || len(prop) < 4 {
			continue
		}
		name, _ := prop[0].(string)
		if name != "fn" && name != "org" {
			continue
		}
		if v, ok := prop[3].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func (s *RDAP) Lookup(ctx context.Context, ip string) (Result, error) {
	if _, err := rejectPrivate(ip); err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://rdap-bootstrap.arin.net/bootstrap/ip/"+ip, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var raw struct {
		Handle   string       `json:"handle"`
		Name     string       `json:"name"`
		Country  string       `json:"country"`
		Type     string       `json:"type"`
		Entities []rdapEntity `json:"entities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return Result{}, fmt.Errorf("decoding response: %w", err)
	}

	org := ""
	for _, e := range raw.Entities {
		if org = e.orgName(); org != "" {
			break
		}
	}

	fields := map[string]string{"handle": raw.Handle, "network_name": raw.Name, "country": raw.Country, "org": org}
	parts := []string{}
	if org != "" {
		parts = append(parts, org)
	} else if raw.Name != "" {
		parts = append(parts, raw.Name)
	}
	if raw.Handle != "" {
		parts = append(parts, raw.Handle)
	}
	if raw.Country != "" {
		parts = append(parts, raw.Country)
	}
	if len(parts) == 0 {
		return Result{}, fmt.Errorf("no registration data returned")
	}
	return Result{Source: s.Key(), Summary: strings.Join(parts, " · "), Fields: fields}, nil
}
