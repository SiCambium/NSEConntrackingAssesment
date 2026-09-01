// Package greynoise implements threatintel.Provider against GreyNoise's
// free, keyless Community API. Confirmed against GreyNoise's own docs
// (https://docs.greynoise.io/docs/using-the-greynoise-community-api):
// endpoint https://api.greynoise.io/v3/community/{ip}, no API key
// required, but capped at 10 lookups/day for unauthenticated callers —
// which is why every call into this client goes through
// threatintel.Manager's cache/queue/rate-limit machinery rather than
// being called directly.
package greynoise

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"conntrackd/internal/threatintel"
)

const baseURL = "https://api.greynoise.io/v3/community/"

type Client struct {
	HTTP *http.Client
}

func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: threatintel.DefaultTimeout}}
}

func (c *Client) Name() string { return "greynoise" }

type communityResponse struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Classification string `json:"classification"`
	Name           string `json:"name"`
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}

func (c *Client) Lookup(ctx context.Context, ip string) (threatintel.Verdict, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+ip, nil)
	if err != nil {
		return threatintel.Verdict{}, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return threatintel.Verdict{}, fmt.Errorf("greynoise: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return threatintel.Verdict{}, fmt.Errorf("greynoise: reading response: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return threatintel.Verdict{}, &threatintel.RateLimitError{Err: fmt.Errorf("greynoise: rate limited (HTTP 429)")}
	}
	if resp.StatusCode != http.StatusOK {
		return threatintel.Verdict{}, fmt.Errorf("greynoise: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var cr communityResponse
	if err := json.Unmarshal(body, &cr); err != nil {
		return threatintel.Verdict{}, fmt.Errorf("greynoise: decoding response: %w", err)
	}

	classification := cr.Classification
	if classification == "" {
		classification = "unknown"
	}
	return threatintel.Verdict{
		Classification: classification,
		IsNoise:        cr.Noise,
		IsRIOT:         cr.Riot,
		Name:           cr.Name,
		Link:           cr.Link,
		Message:        cr.Message,
		RawJSON:        string(body),
	}, nil
}
